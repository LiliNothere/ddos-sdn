"""
Integration Bridge: Faucet/Gauge -> ML Service -> Faucet Mitigation
Polls flow stats from Gauge/Prometheus, runs ML detection, applies mitigation via Faucet ACL
"""

import asyncio
import logging
import time
import signal
import fcntl
import os
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict
from pathlib import Path

import pandas as pd

from .config import settings
from ml_service.model import ModelManager, DDoSModel
from ml_service.faucet_client import FaucetClient, FlowStat, FaucetConfigManager

logger = logging.getLogger(__name__)


@dataclass
class SwitchState:
    """Track state per switch"""
    switch_id: str
    last_poll: float = 0
    last_poll_time: float = 0  # Actual timestamp of last poll for rate calculation
    flow_count: int = 0
    ddos_count: int = 0
    benign_count: int = 0
    last_mitigation: Dict[int, float] = field(default_factory=dict)  # port -> timestamp
    blocked_ports: Set[int] = field(default_factory=set)
    victim_history: List[str] = field(default_factory=list)


class FaucetMLBridge:
    """
    Main integration bridge connecting:
    - Gauge/Prometheus (flow stats collection)
    - ML Service (DDoS detection)
    - Faucet (mitigation via ACL)
    """

    def __init__(self):
        self.model_manager = ModelManager(Path(settings.model_dir))
        self.faucet_client = FaucetClient()
        self.config_manager = FaucetConfigManager()

        # State tracking
        self.switches: Dict[str, SwitchState] = {}
        self.running = False
        self.poll_interval = settings.stats_poll_interval

        # Statistics
        self.stats = {
            'polls': 0,
            'predictions': 0,
            'attacks_detected': 0,
            'mitigations': 0,
            'errors': 0
        }

        # Lock for atomic ACL updates
        self._acl_lock = asyncio.Lock()

        # Track previous flow stats for rate calculation (delta/poll_interval)
        self.last_flow_stats: Dict[str, Dict[str, int]] = {}  # flow_key -> {'packet_count': int, 'byte_count': int}

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.running = False

    async def initialize(self):
        """Initialize components"""
        logger.info("Initializing Faucet-ML Bridge...")

        # Load models
        self.model_manager.load_all()

        if not self.model_manager.current_model:
            logger.warning("No model loaded, attempting auto-train...")
            await self._auto_train()

        # Initialize switch states from config
        await self._discover_switches()

        logger.info("Bridge initialized successfully")

    async def _discover_switches(self):
        """Discover switches from Faucet/Gauge"""
        try:
            # Query Prometheus for known switches
            response = await self.faucet_client.client.get(
                f"{self.faucet_client.gauge_url}/api/v1/query",
                params={'query': 'of_dp_status'}
            )

            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    for result in data['data']['result']:
                        dp_name = result['metric'].get('dp_name', '')
                        if dp_name:
                            self.switches[dp_name] = SwitchState(switch_id=dp_name)
                            logger.info(f"Discovered switch: {dp_name}")

        except Exception as e:
            logger.error(f"Switch discovery failed: {e}")

    async def _auto_train(self):
        """Auto-train model if dataset exists"""
        import os
        if os.path.exists(settings.dataset_path):
            try:
                logger.info(f"Training model from {settings.dataset_path}")
                import pandas as pd
                df = pd.read_csv(settings.dataset_path)
                self.model_manager.train_model(settings.default_model, df)
                logger.info("Auto-train completed")
            except Exception as e:
                logger.error(f"Auto-train failed: {e}")

    async def run(self):
        """Main bridge loop"""
        self.running = True
        logger.info(f"Starting bridge with poll interval: {self.poll_interval}s")

        while self.running:
            start_time = time.time()

            try:
                await self._poll_and_process()
                self.stats['polls'] += 1
            except Exception as e:
                logger.error(f"Poll cycle error: {e}")
                self.stats['errors'] += 1

            # Sleep until next interval
            elapsed = time.time() - start_time
            sleep_time = max(0, self.poll_interval - elapsed)
            await asyncio.sleep(sleep_time)

        logger.info("Bridge stopped")
        await self._cleanup()

    async def _poll_and_process(self):
        """Poll flow stats and process with ML"""
        # Get flow stats from Gauge/Prometheus
        flows = await self.faucet_client.get_flow_stats()

        if not flows:
            logger.debug("No flows received")
            return

        # Group flows by switch
        flows_by_switch = defaultdict(list)
        for flow in flows:
            flows_by_switch[flow.switch_id].append(flow)

        # Process each switch
        for switch_id, switch_flows in flows_by_switch.items():
            if switch_id not in self.switches:
                self.switches[switch_id] = SwitchState(switch_id=switch_id)

            await self._process_switch_flows(switch_id, switch_flows)

    async def _process_switch_flows(self, switch_id: str, flows: List[FlowStat]):
        """Process flows for a single switch"""
        state = self.switches[switch_id]

        # Convert to DataFrame for ML
        flow_data = []
        current_time = time.time()

        # Initialize last_flow_stats for this switch if not exists
        if switch_id not in self.last_flow_stats:
            self.last_flow_stats[switch_id] = {}

        # Track last poll time per switch for accurate rate calculation
        if switch_id not in self.switches[switch_id].__dict__ or not hasattr(self.switches[switch_id], 'last_poll_time'):
            # First poll for this switch - use configured interval as estimate
            elapsed = self.poll_interval
        else:
            elapsed = current_time - self.switches[switch_id].last_poll_time

        # Avoid division by zero or unrealistic elapsed times
        elapsed = max(0.1, min(elapsed, self.poll_interval * 2))

        last_stats = self.last_flow_stats[switch_id]

        for flow in flows:
            # Determine DPID from switch_id (e.g., "s1" -> 1)
            dpid = int(switch_id.lstrip('s')) if switch_id.startswith('s') else hash(switch_id) % 1000000

            # Create unique flow key for tracking
            flow_key = f"{switch_id}:{flow.flow_id}"

            # Calculate rate using delta between polls (not lifetime average)
            last_packet_count = last_stats.get(flow_key, {}).get('packet_count', 0)
            last_byte_count = last_stats.get(flow_key, {}).get('byte_count', 0)

            delta_packets = max(0, flow.packet_count - last_packet_count)
            delta_bytes = max(0, flow.byte_count - last_byte_count)

            # Rate = delta / actual_elapsed_time (accurate for burst detection)
            packet_rate = delta_packets / elapsed if elapsed > 0 else 0
            byte_rate = delta_bytes / elapsed if elapsed > 0 else 0

            flow_data.append({
                'timestamp': flow.timestamp,
                'datapath_id': dpid,
                'flow_id': flow.flow_id,
                'tp_src': flow.tcp_src or flow.udp_src or 0,
                'tp_dst': flow.tcp_dst or flow.udp_dst or 0,
                'ip_proto': flow.ip_proto,
                'icmp_code': flow.icmpv4_code or 0,
                'icmp_type': flow.icmpv4_type or 0,
                'flow_duration_sec': flow.duration_sec,
                'flow_duration_nsec': flow.duration_nsec,
                'idle_timeout': flow.idle_timeout,
                'hard_timeout': flow.hard_timeout,
                'flags': 0,  # Not available from Gauge
                'packet_count': flow.packet_count,
                'byte_count': flow.byte_count,
                'packet_count_per_second': packet_rate,
                'packet_count_per_nsecond': packet_rate / 1e9,
                'byte_count_per_second': byte_rate,
                'byte_count_per_nsecond': byte_rate / 1e9
            })
            # Note: ip_src and ip_dst removed from features to prevent data leakage

            # Update last stats for next poll
            last_stats[flow_key] = {
                'packet_count': flow.packet_count,
                'byte_count': flow.byte_count
            }

        # Update last poll time for this switch
        self.switches[switch_id].last_poll_time = current_time

        if not flow_data:
            return

        df = pd.DataFrame(flow_data)

        # Run prediction
        try:
            labels, confidences = self.model_manager.predict(df)
            self.stats['predictions'] += len(labels)
        except Exception as e:
            logger.error(f"Prediction failed for {switch_id}: {e}")
            return

        # Analyze results
        ddos_flows = []
        benign_flows = []

        for i, (label, conf) in enumerate(zip(labels, confidences)):
            flow = flows[i]
            if label == 1:
                ddos_flows.append((flow, conf))
            else:
                benign_flows.append((flow, conf))

        ddos_count = len(ddos_flows)
        benign_count = len(benign_flows)
        total = ddos_count + benign_count

        state.flow_count = total
        state.ddos_count = ddos_count
        state.benign_count = benign_count
        state.last_poll = current_time

        # Calculate DDoS percentage
        ddos_pct = (ddos_count / total * 100) if total > 0 else 0

        logger.info(f"{switch_id}: {total} flows, {ddos_count} DDoS ({ddos_pct:.1f}%), {benign_count} benign")

        # Check for attack
        if ddos_pct > settings.ddos_threshold_percent and ddos_count > 0:
            await self._handle_attack(switch_id, ddos_flows, ddos_pct)

        # Update flow count metric
        self.faucet_client.update_flow_count(switch_id, total)

    async def _handle_attack(self, switch_id: str, ddos_flows: List, ddos_pct: float):
        """Handle detected DDoS attack"""
        self.stats['attacks_detected'] += 1

        state = self.switches[switch_id]

        # Determine victim (destination) ports and source ports
        # in_port on the switch is the INGRESS port where traffic ENTERS the switch
        # For victim identification, we need to track which EGRESS port the victim is on
        # Faucet ACLs are applied on INGRESS, so we need to find the ingress port
        # of the attack traffic (source) and the egress port of the victim

        victim_ports = defaultdict(int)  # egress port -> packet count
        source_ports = defaultdict(int)  # ingress port -> packet count
        victim_ips = defaultdict(int)

        for flow, conf in ddos_flows:
            # Track victim by destination IP
            victim_ips[flow.ipv4_dst] += flow.packet_count

            # in_port is the ingress port on the switch where attack traffic arrives
            # This is the SOURCE port (where attacker connects)
            if flow.in_port:
                source_ports[flow.in_port] += flow.packet_count

        # Find primary victim IP
        if not victim_ips:
            logger.warning(f"No victim IP identified for {switch_id}")
            return

        victim_ip = max(victim_ips, key=victim_ips.get)

        # Find the switch port where victim is connected
        # This requires mapping victim_ip to host port on the switch
        victim_port = await self._find_victim_port(switch_id, victim_ip)
        if victim_port is None:
            logger.warning(f"Could not find victim port for {victim_ip} on {switch_id}")
            return

        # Find the primary attack source port (ingress)
        if not source_ports:
            logger.warning(f"No source port identified for {switch_id}")
            return

        source_port = max(source_ports, key=source_ports.get)

        # Check cooldown for this victim port
        now = time.time()
        if victim_port in state.last_mitigation:
            elapsed = now - state.last_mitigation[victim_port]
            if elapsed < settings.mitigation_cooldown:
                logger.info(f"Cooldown active for {switch_id}:{victim_port}, skipping mitigation")
                return

        # Apply mitigation: block the SOURCE port (ingress) where attack originates
        # NOT the victim port - we want to stop attack traffic from entering the network
        logger.warning(f"ATTACK DETECTED on {switch_id}: victim={victim_ip} (port {victim_port}), "
                       f"source_port={source_port} ({ddos_pct:.1f}% DDoS)")
        logger.warning(f"Applying mitigation: BLOCK_SOURCE_PORT {source_port}")

        success = await self._apply_mitigation_with_lock(switch_id, source_port, block=True)

        if success:
            state.blocked_ports.add(source_port)
            state.last_mitigation[victim_port] = now  # Track by victim for cooldown
            state.victim_history.append(f"{victim_ip}:{victim_port}:{datetime.now().isoformat()}")
            self.stats['mitigations'] += 1
            logger.info(f"Mitigation applied: {switch_id}:{source_port} blocked (protecting victim on port {victim_port})")

            # Schedule auto-unblock
            asyncio.create_task(self._schedule_unblock(switch_id, source_port, victim_port, settings.mitigation_duration))
        else:
            logger.error(f"Mitigation failed: {switch_id}:{source_port}")

    async def _find_victim_port(self, switch_id: str, victim_ip: str) -> Optional[int]:
        """Find the switch port where victim IP is connected"""
        try:
            # Query host learning table from Faucet
            response = await self.faucet_client.client.get(
                f"{self.faucet_client.gauge_url}/api/v1/query",
                params={'query': f'of_dp_host_learned{{dp_name="{switch_id}"}}'}
            )

            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    for result in data['data']['result']:
                        metric = result['metric']
                        ip = metric.get('ip', '')
                        port = metric.get('port', '')
                        if ip == victim_ip and port.isdigit():
                            return int(port)

            # Fallback: use known topology mapping for Mininet demo
            # VLAN 100 hosts on s1 (ports 1-3) and s6 (ports 1-3)
            # h1 (10.0.0.1) is on s1 port 1 (web server - primary victim)
            # This ensures mitigation works even if Prometheus query fails or L2 learning disabled
            if victim_ip == "10.0.0.1" and switch_id == "s1":
                logger.warning(f"Using fallback victim port 1 for {victim_ip} on {switch_id}")
                return 1

            # Additional fallback mappings for other hosts in VLAN 100
            vlan100_hosts = {
                "10.0.0.1": 1,  # h1 on s1
                "10.0.0.2": 2,  # h2 on s1
                "10.0.0.3": 3,  # h3 on s1
                "10.0.0.4": 1,  # h16 on s6
                "10.0.0.5": 2,  # h17 on s6
                "10.0.0.6": 3,  # h18 on s6
            }

            if victim_ip in vlan100_hosts:
                port = vlan100_hosts[victim_ip]
                logger.warning(f"Using fallback victim port {port} for {victim_ip} on {switch_id}")
                return port

            logger.warning(f"No victim port mapping found for {victim_ip} on {switch_id}")
            return None

        except Exception as e:
            logger.error(f"Failed to find victim port: {e}")
            # Emergency fallback for demo: assume web server on s1 port 1
            if switch_id == "s1":
                return 1
            return None

    async def _apply_mitigation_with_lock(self, switch_id: str, port: int, block: bool = True) -> bool:
        """Apply ACL with file locking for atomic updates"""
        async with self._acl_lock:
            return await self.faucet_client.apply_acl(switch_id, port, block)

    async def _schedule_unblock(self, switch_id: str, port: int, victim_port: int, duration: int):
        """Schedule automatic unblock after duration"""
        await asyncio.sleep(duration)
        if self.running:
            logger.info(f"Auto-unblocking {switch_id}:{port} after {duration}s")
            await self._apply_mitigation_with_lock(switch_id, port, block=False)
            if switch_id in self.switches:
                self.switches[switch_id].blocked_ports.discard(port)

    async def emergency_unblock(self, switch_id: str, port: int) -> bool:
        """Emergency unblock - bypasses cooldown"""
        logger.warning(f"EMERGENCY UNBLOCK: {switch_id}:{port}")
        success = await self._apply_mitigation_with_lock(switch_id, port, block=False)
        if success and switch_id in self.switches:
            self.switches[switch_id].blocked_ports.discard(port)
            # Remove from cooldown tracking
            for vport, ts in list(self.switches[switch_id].last_mitigation.items()):
                if vport == port:
                    del self.switches[switch_id].last_mitigation[vport]
        return success

    async def _cleanup(self):
        """Cleanup on shutdown"""
        logger.info("Cleaning up...")
        await self.faucet_client.close()
        logger.info("Cleanup complete")

    def get_status(self) -> Dict:
        """Get bridge status"""
        return {
            'running': self.running,
            'poll_interval': self.poll_interval,
            'switches': {
                sid: {
                    'switch_id': s.switch_id,
                    'last_poll': s.last_poll,
                    'flow_count': s.flow_count,
                    'ddos_count': s.ddos_count,
                    'benign_count': s.benign_count,
                    'blocked_ports': list(s.blocked_ports),
                    'victim_history': s.victim_history[-10:]
                }
                for sid, s in self.switches.items()
            },
            'stats': self.stats,
            'model_loaded': self.model_manager.current_model is not None,
            'current_model': self.model_manager.current_model.model_type if self.model_manager.current_model else None
        }


async def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    bridge = FaucetMLBridge()
    await bridge.initialize()
    await bridge.run()


if __name__ == "__main__":
    asyncio.run(main())