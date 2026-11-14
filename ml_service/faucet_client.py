"""
Faucet Controller Client for ML Service Integration
Communicates with Faucet via REST API and Prometheus metrics
"""

import asyncio
import logging
import time
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

import httpx
import yaml
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, push_to_gateway, generate_latest

from .config import settings

logger = logging.getLogger(__name__)

# fcntl is Unix-only; provide fallback for Windows
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False
    import msvcrt  # Windows file locking


@dataclass
class FlowStat:
    """Flow statistics from Faucet/Gauge"""
    switch_id: str
    flow_id: str
    in_port: int
    eth_type: int
    ipv4_src: str
    ipv4_dst: str
    ip_proto: int
    tcp_src: Optional[int] = None
    tcp_dst: Optional[int] = None
    udp_src: Optional[int] = None
    udp_dst: Optional[int] = None
    icmpv4_type: Optional[int] = None
    icmpv4_code: Optional[int] = None
    packet_count: int = 0
    byte_count: int = 0
    duration_sec: int = 0
    duration_nsec: int = 0
    idle_timeout: int = 0
    hard_timeout: int = 0
    priority: int = 0
    cookie: int = 0
    timestamp: float = 0


@dataclass
class PortStat:
    """Port statistics from Faucet/Gauge"""
    switch_id: str
    port_number: int
    port_name: str
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_errors: int = 0
    rx_errors: int = 0
    dropped: int = 0
    timestamp: float = 0


class FaucetClient:
    """Client for communicating with Faucet controller"""

    def __init__(self):
        self.faucet_url = f"http://{settings.faucet_host}:{settings.faucet_rest_port}"
        self.gauge_url = f"http://{settings.faucet_host}:{settings.gauge_prometheus_port}"
        self.acl_name = settings.faucet_acl_name
        self.client = httpx.AsyncClient(timeout=30.0)

        # Prometheus metrics for ML service
        self.registry = CollectorRegistry()
        self.predictions_total = Counter(
            'ddos_predictions_total',
            'Total predictions made',
            ['result'],
            registry=self.registry
        )
        self.attack_detected = Counter(
            'ddos_attacks_detected_total',
            'Total DDoS attacks detected',
            ['switch', 'victim'],
            registry=self.registry
        )
        self.mitigation_actions = Counter(
            'ddos_mitigation_actions_total',
            'Total mitigation actions taken',
            ['action', 'switch', 'result'],
            registry=self.registry
        )
        self.prediction_latency = Histogram(
            'ddos_prediction_latency_seconds',
            'Prediction latency in seconds',
            registry=self.registry
        )
        self.flow_count = Gauge(
            'ddos_flows_processed',
            'Number of flows processed',
            ['switch'],
            registry=self.registry
        )
        self.acl_operations = Counter(
            'ddos_acl_operations_total',
            'Total ACL operations',
            ['operation', 'switch', 'result'],
            registry=self.registry
        )

    async def close(self):
        await self.client.aclose()

    async def get_flow_stats(self) -> List[FlowStat]:
        """Fetch flow statistics from Gauge/Prometheus"""
        try:
            # Query Prometheus for flow stats
            queries = {
                'packet_count': 'of_flow_packet_count',
                'byte_count': 'of_flow_byte_count',
                'duration_sec': 'of_flow_duration_seconds',
                'duration_nsec': 'of_flow_duration_nanoseconds',
                'idle_timeout': 'of_flow_idle_timeout',
                'hard_timeout': 'of_flow_hard_timeout',
                'priority': 'of_flow_priority',
                'cookie': 'of_flow_cookie',
                'in_port': 'of_flow_match_in_port',
                'eth_type': 'of_flow_match_eth_type',
                'ipv4_src': 'of_flow_match_ipv4_src',
                'ipv4_dst': 'of_flow_match_ipv4_dst',
                'ip_proto': 'of_flow_match_ip_proto',
                'tcp_src': 'of_flow_match_tcp_src',
                'tcp_dst': 'of_flow_match_tcp_dst',
                'udp_src': 'of_flow_match_udp_src',
                'udp_dst': 'of_flow_match_udp_dst',
                'icmpv4_type': 'of_flow_match_icmpv4_type',
                'icmpv4_code': 'of_flow_match_icmpv4_code',
            }

            flows_by_id = {}

            for metric_name, prom_query in queries.items():
                response = await self.client.get(
                    f"{self.gauge_url}/api/v1/query",
                    params={'query': prom_query}
                )

                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        for result in data['data']['result']:
                            metric = result['metric']
                            value = float(result['value'][1])

                            switch = metric.get('dp_name', metric.get('dp_id', 'unknown'))
                            flow_cookie = metric.get('cookie', '')

                            # Create unique flow key
                            flow_key = f"{switch}:{flow_cookie}"

                            if flow_key not in flows_by_id:
                                flows_by_id[flow_key] = FlowStat(
                                    switch_id=switch,
                                    flow_id=flow_key,
                                    timestamp=time.time()
                                )

                            flow = flows_by_id[flow_key]

                            # Map metric to flow attribute
                            if metric_name in ['packet_count', 'byte_count', 'duration_sec',
                                               'duration_nsec', 'idle_timeout', 'hard_timeout',
                                               'priority', 'cookie']:
                                setattr(flow, metric_name, int(value))
                            elif metric_name in ['in_port', 'eth_type', 'ip_proto']:
                                setattr(flow, metric_name, int(value))
                            elif metric_name in ['ipv4_src', 'ipv4_dst']:
                                # Convert from Prometheus format (stored as string representation of int)
                                try:
                                    ip_int = int(value)
                                    # Convert integer IP to dotted notation
                                    ip_str = '.'.join(str((ip_int >> (8 * i)) & 0xFF) for i in [3, 2, 1, 0])
                                    setattr(flow, metric_name, ip_str)
                                except (ValueError, TypeError):
                                    setattr(flow, metric_name, '0.0.0.0')
                            elif metric_name in ['tcp_src', 'tcp_dst', 'udp_src', 'udp_dst',
                                                 'icmpv4_type', 'icmpv4_code']:
                                if value > 0:
                                    setattr(flow, metric_name, int(value))

            return list(flows_by_id.values())

        except Exception as e:
            logger.error(f"Failed to get flow stats: {e}")
            return []

    async def get_port_stats(self) -> List[PortStat]:
        """Fetch port statistics"""
        try:
            queries = {
                'tx_packets': 'of_port_tx_packets',
                'rx_packets': 'of_port_rx_packets',
                'tx_bytes': 'of_port_tx_bytes',
                'rx_bytes': 'of_port_rx_bytes',
                'tx_errors': 'of_port_tx_errors',
                'rx_errors': 'of_port_rx_errors',
                'dropped': 'of_port_dropped',
            }

            ports_by_id = {}

            for metric_name, prom_query in queries.items():
                response = await self.client.get(
                    f"{self.gauge_url}/api/v1/query",
                    params={'query': prom_query}
                )

                if response.status_code == 200:
                    data = response.json()
                    if data['status'] == 'success':
                        for result in data['data']['result']:
                            metric = result['metric']
                            value = float(result['value'][1])

                            switch = metric.get('dp_name', metric.get('dp_id', 'unknown'))
                            port = metric.get('port', metric.get('port_name', '0'))

                            port_key = f"{switch}:{port}"

                            if port_key not in ports_by_id:
                                ports_by_id[port_key] = PortStat(
                                    switch_id=switch,
                                    port_number=int(port) if port.isdigit() else 0,
                                    port_name=port,
                                    timestamp=time.time()
                                )

                            port_stat = ports_by_id[port_key]
                            setattr(port_stat, metric_name, int(value))

            return list(ports_by_id.values())

        except Exception as e:
            logger.error(f"Failed to get port stats: {e}")
            return []

    async def apply_acl(self, switch_id: str, port: int, block: bool = True) -> bool:
        """Apply ACL to block/unblock port on switch with atomic file operations.

        Updates the block-malicious.yaml ACL file which is included in faucet.yaml.
        The ACL is applied at VLAN level in faucet.yaml, so we just update the rules.
        """
        try:
            # Skip trunk/inter-switch ports (configurable threshold)
            # These are high ports that carry multiple VLANs
            trunk_threshold = settings.faucet_trunk_port_threshold
            if port >= trunk_threshold:
                logger.warning(f"Refusing to block trunk port {port} on {switch_id} (threshold: {trunk_threshold})")
                self.acl_operations.labels(
                    operation='block' if block else 'unblock',
                    switch=switch_id,
                    result='skipped_trunk'
                ).inc()
                return False

            acl_rule = {
                "rule": {
                    "in_port": port,
                    "actions": {
                        "allow": not block
                    }
                }
            }

            # Write to ACL file (Faucet watches for changes) with locking
            acl_file = Path(f"/etc/faucet/acls/{self.acl_name}.yaml")

            # Atomic write with file locking
            success = await self._atomic_acl_update(acl_file, acl_rule, block)

            if success:
                # Trigger Faucet reload via SIGHUP
                await self.reload_faucet_config()

                self.acl_operations.labels(
                    operation='block' if block else 'unblock',
                    switch=switch_id,
                    result='success'
                ).inc()

                logger.info(f"{'Blocked' if block else 'Unblocked'} port {port} on {switch_id}")
                return True
            else:
                self.acl_operations.labels(
                    operation='block' if block else 'unblock',
                    switch=switch_id,
                    result='failed'
                ).inc()
                return False

        except Exception as e:
            logger.error(f"Failed to apply ACL: {e}")
            self.acl_operations.labels(
                operation='block' if block else 'unblock',
                switch=switch_id,
                result='error'
            ).inc()
            return False

    async def _atomic_acl_update(self, acl_file: Path, new_rule: Dict, block: bool) -> bool:
        """Atomically update ACL file with file locking (cross-platform).

        The ACL file must be wrapped in an 'acls:' key for Faucet to read it properly.
        Format: {'acls': {'block-malicious': [rule1, rule2, ...]}}
        """
        try:
            # Ensure directory exists
            acl_file.parent.mkdir(parents=True, exist_ok=True)

            # Use file locking for atomic updates
            # Open file for reading/writing
            with open(acl_file, 'a+') as f:
                # Cross-platform file locking
                if HAS_FCNTL:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                else:
                    # Windows: use msvcrt locking
                    # Get file size before operations to ensure consistent lock length
                    lock_length = os.path.getsize(acl_file) or 1
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, lock_length)

                try:
                    # Read existing ACL
                    f.seek(0)
                    content = f.read()
                    data = yaml.safe_load(content) or {}

                    # Extract acls dict or create new one
                    acls = data.get('acls', {})
                    acl_name = self.acl_name

                    # Get or create the ACL rule list
                    rules = acls.get(acl_name, [])

                    # Update or add rule
                    rule_exists = False
                    port = new_rule['rule']['in_port']

                    for rule in rules:
                        if rule.get('rule', {}).get('in_port') == port:
                            rule['rule']['actions']['allow'] = not block
                            rule_exists = True
                            break

                    if not rule_exists:
                        rules.append(new_rule)

                    # Update the ACL structure
                    acls[acl_name] = rules
                    data['acls'] = acls

                    # Write back with proper structure
                    f.seek(0)
                    f.truncate()
                    yaml.dump(data, f, default_flow_style=False)
                    f.flush()
                    os.fsync(f.fileno())

                finally:
                    # Release lock
                    if HAS_FCNTL:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                    else:
                        # Use same lock_length as when acquiring lock
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, lock_length)

            return True

        except Exception as e:
            logger.error(f"Atomic ACL update failed: {e}")
            return False

    async def reload_faucet_config(self) -> bool:
        """Trigger Faucet configuration reload via SIGHUP signal.

        REST API reload is deprecated. SIGHUP causes Faucet to reload
        configuration files including ACLs without restarting.
        """
        try:
            # Send SIGHUP to Faucet process
            # Faucet typically runs as 'faucet' user or root
            # We use pkill to find and signal the process
            import subprocess
            result = subprocess.run(
                ['pkill', '-HUP', '-f', 'faucet.faucet'],
                capture_output=True,
                timeout=5
            )
            # pkill returns 0 if process found and signaled, 1 if no process found
            # Return code 1 means no Faucet process was running - treat as failure
            if result.returncode == 0:
                logger.info("Sent SIGHUP to Faucet process for config reload")
                return True
            elif result.returncode == 1:
                logger.error("No Faucet process found (pkill returned 1) - config not reloaded")
                return False
            else:
                logger.error(f"Failed to send SIGHUP (return code {result.returncode}): {result.stderr.decode()}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("SIGHUP command timed out")
            return False
        except Exception as e:
            logger.error(f"Failed to reload Faucet config via SIGHUP: {e}")
            return False

    async def get_switch_status(self) -> Dict[str, Any]:
        """Get Faucet switch status"""
        try:
            response = await self.client.get(f"{self.faucet_url}/metrics")
            if response.status_code == 200:
                return {"status": "ok", "metrics": response.text[:1000]}
            return {"status": "error"}
        except Exception as e:
            logger.error(f"Failed to get switch status: {e}")
            return {"status": "error", "error": str(e)}

    def record_prediction(self, is_ddos: bool, switch: str = "", victim: str = "") -> None:
        """Record prediction metrics"""
        self.predictions_total.labels(result='ddos' if is_ddos else 'benign').inc()
        if is_ddos and victim:
            self.attack_detected.labels(switch=switch, victim=victim).inc()

    def record_mitigation(self, action: str, switch: str, success: bool) -> None:
        """Record mitigation action"""
        self.mitigation_actions.labels(
            action=action,
            switch=switch,
            result='success' if success else 'failed'
        ).inc()

    def record_latency(self, latency: float) -> None:
        """Record prediction latency"""
        self.prediction_latency.observe(latency)

    def update_flow_count(self, switch: str, count: int) -> None:
        """Update flow count gauge"""
        self.flow_count.labels(switch=switch).set(count)

    def push_metrics(self, gateway: str = "pushgateway:9091") -> None:
        """Push metrics to Prometheus Pushgateway"""
        try:
            push_to_gateway(gateway, job='ddos_ml_service', registry=self.registry)
        except Exception as e:
            logger.warning(f"Failed to push metrics: {e}")

    def get_metrics(self) -> bytes:
        """Get Prometheus metrics in text format"""
        return generate_latest(self.registry)


class FaucetConfigManager:
    """Manage Faucet configuration files"""

    def __init__(self, config_dir: Path = Path("/etc/faucet")):
        self.config_dir = config_dir
        self.acl_dir = config_dir / "acls"
        self.acl_dir.mkdir(parents=True, exist_ok=True)

    def write_acl(self, name: str, rules: List[Dict]) -> bool:
        """Write ACL file atomically with proper 'acls:' wrapper"""
        try:
            acl_file = self.acl_dir / f"{name}.yaml"
            temp_file = acl_file.with_suffix('.tmp')

            # Wrap rules in 'acls:' dict for Faucet
            data = {'acls': {name: rules}}

            with open(temp_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)

            temp_file.replace(acl_file)
            return True
        except Exception as e:
            logger.error(f"Failed to write ACL {name}: {e}")
            return False

    def read_acl(self, name: str) -> List[Dict]:
        """Read ACL file"""
        try:
            acl_file = self.acl_dir / f"{name}.yaml"
            if acl_file.exists():
                with open(acl_file) as f:
                    data = yaml.safe_load(f) or {}
                    # Extract rules from 'acls' wrapper
                    return data.get('acls', {}).get(name, [])
            return []
        except Exception as e:
            logger.error(f"Failed to read ACL {name}: {e}")
            return []

    def add_block_rule(self, acl_name: str, port: int, switch: str = None) -> bool:
        """Add port block rule to ACL"""
        rules = self.read_acl(acl_name)

        # Check if rule exists
        for rule in rules:
            if rule.get('rule', {}).get('in_port') == port:
                rule['rule']['actions']['allow'] = False
                return self.write_acl(acl_name, rules)

        # Add new rule
        new_rule = {
            "rule": {
                "in_port": port,
                "actions": {"allow": False}
            }
        }
        if switch:
            new_rule["rule"]["dp_name"] = switch

        rules.append(new_rule)
        return self.write_acl(acl_name, rules)

    def remove_block_rule(self, acl_name: str, port: int) -> bool:
        """Remove port block rule from ACL"""
        rules = self.read_acl(acl_name)

        # Remove rule for this port
        rules = [r for r in rules if r.get('rule', {}).get('in_port') != port]

        return self.write_acl(acl_name, rules)

    def generate_faucet_config(self, switches: List[Dict]) -> str:
        """Generate Faucet config from topology"""
        # This would generate faucet.yaml from topology description
        # For now, return template
        return ""