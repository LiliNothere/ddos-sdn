#!/usr/bin/env python3
"""
Generate Synthetic DDoS Dataset for Training
Creates realistic benign and DDoS flow data matching the model's feature columns
"""

import argparse
import random
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Tuple
import sys

# Import centralized feature columns from config
# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_service.config import NUMERIC_FEATURE_COLUMNS, TARGET_COLUMN

# Full columns for CSV output (no IP columns)
FULL_FEATURE_COLUMNS = NUMERIC_FEATURE_COLUMNS.copy()


class DDoSDatasetGenerator:
    """Generate synthetic DDoS detection dataset"""

    # Common ports
    HTTP_PORTS = [80, 8080, 8000, 8888]
    HTTPS_PORTS = [443, 8443]
    DNS_PORTS = [53]
    SSH_PORTS = [22]
    COMMON_PORTS = HTTP_PORTS + HTTPS_PORTS + DNS_PORTS + SSH_PORTS + [21, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017]

    # IP ranges for different VLANs (matching faucet.yaml)
    VLAN_IPS = {
        100: "10.0.0.",    # h1-h3, h16-h18
        200: "10.0.1.",    # h4-h6
        300: "10.0.2.",    # h7-h9
        400: "10.0.3.",    # h10-h12
        500: "10.0.4.",    # h13-h15
    }

    def __init__(self, seed: int = 42):
        self.seed = seed
        random.seed(seed)
        np.random.seed(seed)
        self.flow_counter = 0
        self.datapath_counter = 0

    def _next_flow_id(self) -> str:
        self.flow_counter += 1
        return f"flow_{self.flow_counter:08d}"

    def _next_datapath_id(self) -> int:
        # Cycle through 6 switches (dp_id 1-6)
        self.datapath_counter = (self.datapath_counter % 6) + 1
        return self.datapath_counter

    def _random_ip(self, vlan: int = None) -> str:
        """Generate random IP within VLAN range (kept for internal logic but not in output)"""
        if vlan is None:
            vlan = random.choice(list(self.VLAN_IPS.keys()))
        base = self.VLAN_IPS[vlan]
        return f"{base}{random.randint(1, 254)}"

    def _random_port(self, is_common: bool = True) -> int:
        """Generate random port"""
        if is_common and random.random() < 0.7:
            return random.choice(self.COMMON_PORTS)
        return random.randint(1024, 65535)

    def _make_duration_multiple_of_10(self, base_duration: int) -> int:
        """Ensure flow_duration_sec is a multiple of 10 (matching Gauge poll interval)"""
        if base_duration <= 0:
            return 10
        # Round up to nearest multiple of 10
        return ((base_duration + 9) // 10) * 10

    def generate_benign_flow(self, timestamp: float = None) -> dict:
        """Generate a single benign flow"""
        if timestamp is None:
            timestamp = random.uniform(0, 86400)  # Random time in a day

        # Benign traffic: lower packet counts, varied durations, common ports
        proto = random.choices([6, 17, 1], weights=[0.6, 0.35, 0.05])[0]  # TCP, UDP, ICMP

        src_vlan = random.choice(list(self.VLAN_IPS.keys()))
        dst_vlan = random.choice(list(self.VLAN_IPS.keys()))

        # Base duration, then make it multiple of 10
        if proto == 6:  # TCP
            if random.random() < 0.5:
                # Web traffic: short bursts
                base_duration = random.randint(1, 30)
            else:
                # SSH/other: longer
                base_duration = random.randint(60, 3600)
        elif proto == 17:  # UDP
            if random.random() < 0.5:
                # DNS: very short
                base_duration = random.randint(0, 2)
            else:
                base_duration = random.randint(1, 60)
        else:  # ICMP
            base_duration = random.randint(0, 5)

        flow_duration_sec = self._make_duration_multiple_of_10(base_duration)

        flow = {
            'timestamp': timestamp,
            'datapath_id': self._next_datapath_id(),
            'flow_id': self._next_flow_id(),
            'tp_src': self._random_port(),
            'tp_dst': self._random_port(),
            'ip_proto': proto,
            'icmp_code': 0,
            'icmp_type': 0,
            'flow_duration_sec': flow_duration_sec,
            'flow_duration_nsec': random.randint(0, 999999999),
            'idle_timeout': random.randint(10, 300),
            'hard_timeout': random.randint(300, 3600),
            'flags': 0,  # Fixed to 0 for DecisionTree compatibility
            'packet_count': 0,
            'byte_count': 0,
            'packet_count_per_second': 0.0,
            'packet_count_per_nsecond': 0.0,
            'byte_count_per_second': 0.0,
            'byte_count_per_nsecond': 0.0
        }

        # Set protocol-specific fields
        if proto == 1:  # ICMP
            flow['icmp_type'] = random.choice([0, 8, 3, 11])  # echo reply, request, dest unreachable, time exceeded
            flow['icmp_code'] = 0
            flow['tp_src'] = 0
            flow['tp_dst'] = 0

        # Generate realistic benign traffic patterns
        if proto == 6:  # TCP
            # Web browsing, API calls, etc.
            if flow['tp_dst'] in self.HTTP_PORTS + self.HTTPS_PORTS:
                # HTTP traffic: short bursts
                flow['packet_count'] = random.randint(10, 500)
                flow['byte_count'] = flow['packet_count'] * random.randint(500, 1500)
            elif flow['tp_dst'] in self.SSH_PORTS:
                # SSH: long-lived, low rate
                flow['packet_count'] = random.randint(100, 2000)
                flow['byte_count'] = flow['packet_count'] * random.randint(200, 800)
            else:
                flow['packet_count'] = random.randint(5, 1000)
                flow['byte_count'] = flow['packet_count'] * random.randint(100, 2000)

        elif proto == 17:  # UDP
            if flow['tp_dst'] in self.DNS_PORTS:
                # DNS: very short
                flow['packet_count'] = random.randint(2, 20)
                flow['byte_count'] = flow['packet_count'] * random.randint(100, 500)
            else:
                flow['packet_count'] = random.randint(5, 200)
                flow['byte_count'] = flow['packet_count'] * random.randint(200, 1000)

        else:  # ICMP
            flow['packet_count'] = random.randint(1, 10)
            flow['byte_count'] = flow['packet_count'] * random.randint(64, 512)

        # Calculate rates based on flow_duration_sec (multiple of 10)
        dur = max(flow['flow_duration_sec'], 1)
        flow['packet_count_per_second'] = flow['packet_count'] / dur
        flow['byte_count_per_second'] = flow['byte_count'] / dur
        flow['packet_count_per_nsecond'] = flow['packet_count'] / (dur * 1e9)
        flow['byte_count_per_nsecond'] = flow['byte_count'] / (dur * 1e9)

        return flow

    def generate_ddos_flow(self, timestamp: float = None, attack_type: str = None) -> dict:
        """Generate a single DDoS flow"""
        if timestamp is None:
            timestamp = random.uniform(0, 86400)

        if attack_type is None:
            attack_type = random.choice(['syn_flood', 'udp_flood', 'icmp_flood', 'http_flood', 'slowloris'])

        # DDoS traffic: high packet rates, specific patterns
        proto_map = {
            'syn_flood': 6,
            'udp_flood': 17,
            'icmp_flood': 1,
            'http_flood': 6,
            'slowloris': 6,
        }
        proto = proto_map.get(attack_type, 6)

        # Attackers from external (simulated) or internal compromised hosts
        # Use IPs outside normal VLAN ranges for external attackers
        if random.random() < 0.7:
            # External attacker
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        else:
            # Internal compromised
            src_ip = self._random_ip()

        # Victim is typically in VLAN 100 (web servers)
        dst_vlan = 100
        dst_ip = self._random_ip(dst_vlan)

        # Base duration for attack flows
        if attack_type == 'syn_flood':
            base_duration = random.randint(0, 2)
        elif attack_type == 'udp_flood':
            base_duration = random.randint(1, 10)
        elif attack_type == 'icmp_flood':
            base_duration = random.randint(1, 30)
        elif attack_type == 'http_flood':
            base_duration = random.randint(1, 60)
        elif attack_type == 'slowloris':
            base_duration = random.randint(300, 3600)
        else:
            base_duration = random.randint(1, 10)

        flow_duration_sec = self._make_duration_multiple_of_10(base_duration)

        flow = {
            'timestamp': timestamp,
            'datapath_id': self._next_datapath_id(),
            'flow_id': self._next_flow_id(),
            'tp_src': self._random_port(is_common=False),
            'tp_dst': self._get_target_port(attack_type),
            'ip_proto': proto,
            'icmp_code': 0,
            'icmp_type': 0,
            'flow_duration_sec': flow_duration_sec,
            'flow_duration_nsec': random.randint(0, 999999999),
            'idle_timeout': random.randint(1, 10),  # Short timeouts for attack flows
            'hard_timeout': random.randint(10, 60),
            'flags': 0,  # Fixed to 0 for DecisionTree compatibility (was 2 for SYN)
            'packet_count': 0,
            'byte_count': 0,
            'packet_count_per_second': 0.0,
            'packet_count_per_nsecond': 0.0,
            'byte_count_per_second': 0.0,
            'byte_count_per_nsecond': 0.0
        }

        if proto == 1:  # ICMP
            flow['icmp_type'] = 8  # Echo request
            flow['icmp_code'] = 0
            flow['tp_src'] = 0
            flow['tp_dst'] = 0

        # Generate attack-specific patterns
        if attack_type == 'syn_flood':
            # Many SYN packets, few bytes each, very short flows
            flow['packet_count'] = random.randint(100, 10000)
            flow['byte_count'] = flow['packet_count'] * random.randint(40, 80)  # Small SYN packets

        elif attack_type == 'udp_flood':
            # High volume UDP
            flow['packet_count'] = random.randint(500, 50000)
            flow['byte_count'] = flow['packet_count'] * random.randint(512, 1500)

        elif attack_type == 'icmp_flood':
            # ICMP echo requests
            flow['packet_count'] = random.randint(100, 20000)
            flow['byte_count'] = flow['packet_count'] * random.randint(64, 1500)

        elif attack_type == 'http_flood':
            # HTTP GET/POST floods
            flow['packet_count'] = random.randint(50, 5000)
            flow['byte_count'] = flow['packet_count'] * random.randint(500, 2000)

        elif attack_type == 'slowloris':
            # Slowloris: long duration, low packet rate
            flow['packet_count'] = random.randint(10, 200)
            flow['byte_count'] = flow['packet_count'] * random.randint(200, 1000)

        # Calculate rates (high for DDoS) based on flow_duration_sec (multiple of 10)
        dur = max(flow['flow_duration_sec'], 1)
        flow['packet_count_per_second'] = flow['packet_count'] / dur
        flow['byte_count_per_second'] = flow['byte_count'] / dur
        flow['packet_count_per_nsecond'] = flow['packet_count'] / (dur * 1e9)
        flow['byte_count_per_nsecond'] = flow['byte_count'] / (dur * 1e9)

        return flow

    def _get_target_port(self, attack_type: str) -> int:
        """Get target port based on attack type"""
        if attack_type in ['http_flood', 'slowloris']:
            return random.choice(self.HTTP_PORTS + self.HTTPS_PORTS)
        elif attack_type == 'syn_flood':
            return random.choice(self.HTTP_PORTS + self.HTTPS_PORTS + self.SSH_PORTS + [21, 25, 3306, 5432])
        elif attack_type == 'udp_flood':
            return random.choice(self.DNS_PORTS + [123, 161, 162, 500, 4500])  # NTP, SNMP, IKE
        else:
            return random.choice(self.COMMON_PORTS)

    def generate_dataset(self, n_benign: int, n_ddos: int,
                         time_span: int = 86400) -> pd.DataFrame:
        """Generate complete dataset"""
        print(f"Generating {n_benign} benign flows + {n_ddos} DDoS flows...")

        flows = []

        # Generate benign flows distributed over time
        for i in range(n_benign):
            ts = random.uniform(0, time_span)
            flows.append({**self.generate_benign_flow(ts), TARGET_COLUMN: 0})
            if (i + 1) % 10000 == 0:
                print(f"  Benign: {i + 1}/{n_benign}")

        # Generate DDoS flows in bursts (attacks happen in windows)
        attack_windows = max(1, n_ddos // 5000)  # Group attacks into windows
        flows_per_window = n_ddos // attack_windows

        attack_types = ['syn_flood', 'udp_flood', 'icmp_flood', 'http_flood', 'slowloris']

        for window in range(attack_windows):
            window_start = random.uniform(0, time_span)
            window_duration = random.uniform(10, 300)  # Attack lasts 10-300 seconds

            for i in range(flows_per_window):
                ts = window_start + random.uniform(0, window_duration)
                attack_type = random.choice(attack_types)
                flows.append({**self.generate_ddos_flow(ts, attack_type), TARGET_COLUMN: 1})

            if (window + 1) % 10 == 0:
                print(f"  DDoS window: {window + 1}/{attack_windows}")

        # Handle remainder
        remainder = n_ddos - (attack_windows * flows_per_window)
        for i in range(remainder):
            ts = random.uniform(0, time_span)
            attack_type = random.choice(attack_types)
            flows.append({**self.generate_ddos_flow(ts, attack_type), TARGET_COLUMN: 1})

        print("Creating DataFrame...")
        df = pd.DataFrame(flows)

        # Shuffle
        df = df.sample(frac=1, random_state=self.seed).reset_index(drop=True)

        print(f"Dataset created: {len(df)} total flows")
        print(f"  Benign: {(df[TARGET_COLUMN] == 0).sum()}")
        print(f"  DDoS:   {(df[TARGET_COLUMN] == 1).sum()}")

        return df


def main():
    parser = argparse.ArgumentParser(description='Generate synthetic DDoS dataset')
    parser.add_argument('-b', '--benign', type=int, default=50000,
                        help='Number of benign flows (default: 50000)')
    parser.add_argument('-d', '--ddos', type=int, default=50000,
                        help='Number of DDoS flows (default: 50000)')
    parser.add_argument('-o', '--output', type=str, default='data/FlowStatsfile.csv',
                        help='Output CSV path (default: data/FlowStatsfile.csv)')
    parser.add_argument('--seed', type=int, default=42, help='Random seed')
    parser.add_argument('--time-span', type=int, default=86400,
                        help='Time span in seconds (default: 86400 = 1 day)')

    args = parser.parse_args()

    # Create output directory
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate dataset
    generator = DDoSDatasetGenerator(seed=args.seed)
    df = generator.generate_dataset(args.benign, args.ddos, args.time_span)

    # Ensure all feature columns are present and in correct order (no IP columns)
    cols = FULL_FEATURE_COLUMNS + [TARGET_COLUMN]
    df = df[cols]

    # Save
    print(f"\nSaving to {output_path}...")
    df.to_csv(output_path, index=False)
    print(f"Done! File size: {output_path.stat().st_size / 1024 / 1024:.2f} MB")

    # Print stats
    print("\nFeature statistics:")
    print(df.describe())

    print("\nLabel distribution:")
    print(df[TARGET_COLUMN].value_counts().sort_index())


if __name__ == '__main__':
    main()