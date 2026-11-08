"""
Mininet Topology for DDoS SDN Testing
6 Switches, 18 Hosts, 5 VLANs - Compatible with Faucet Controller
"""

import sys
import os
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo


class DDoSTopo(Topo):
    """6-switch, 18-host topology with 5 VLANs for Faucet"""

    def build(self):
        # Add switches with specific dpid (matching faucet.yaml)
        switches = {}
        for i in range(1, 7):
            dpid = f'{i:x}'  # 0x1, 0x2, 0x3, 0x4, 0x5, 0x6
            switches[f's{i}'] = self.addSwitch(f's{i}', dpid=dpid, protocols='OpenFlow13')

        # Add hosts with IPs matching VLANs
        # VLAN 100: h1, h2, h3, h16, h17, h18 (10.0.0.0/24)
        # VLAN 200: h4, h5, h6 (10.0.1.0/24)
        # VLAN 300: h7, h8, h9 (10.0.2.0/24)
        # VLAN 400: h10, h11, h12 (10.0.3.0/24)
        # VLAN 500: h13, h14, h15 (10.0.4.0/24)

        hosts = {}
        host_ips = {
            'h1': '10.0.0.1/24',   # Web server (target)
            'h2': '10.0.0.2/24',
            'h3': '10.0.0.3/24',
            'h4': '10.0.1.1/24',
            'h5': '10.0.1.2/24',
            'h6': '10.0.1.3/24',
            'h7': '10.0.2.1/24',
            'h8': '10.0.2.2/24',
            'h9': '10.0.2.3/24',
            'h10': '10.0.3.1/24',
            'h11': '10.0.3.2/24',
            'h12': '10.0.3.3/24',
            'h13': '10.0.4.1/24',
            'h14': '10.0.4.2/24',
            'h15': '10.0.4.3/24',
            'h16': '10.0.0.4/24',
            'h17': '10.0.0.5/24',
            'h18': '10.0.0.6/24',
        }

        for name, ip in host_ips.items():
            hosts[name] = self.addHost(name, ip=ip)

        # Connect hosts to switches (matching faucet.yaml port mapping)
        # s1: h1(1), h2(2), h3(3), s2(4)
        self.addLink(hosts['h1'], switches['s1'], port1=0, port2=1)
        self.addLink(hosts['h2'], switches['s1'], port1=0, port2=2)
        self.addLink(hosts['h3'], switches['s1'], port1=0, port2=3)

        # s2: h4(1), h5(2), h6(3), s1(4), s3(5)
        self.addLink(hosts['h4'], switches['s2'], port1=0, port2=1)
        self.addLink(hosts['h5'], switches['s2'], port1=0, port2=2)
        self.addLink(hosts['h6'], switches['s2'], port1=0, port2=3)

        # s3: h7(1), h8(2), h9(3), s2(4), s4(5)
        self.addLink(hosts['h7'], switches['s3'], port1=0, port2=1)
        self.addLink(hosts['h8'], switches['s3'], port1=0, port2=2)
        self.addLink(hosts['h9'], switches['s3'], port1=0, port2=3)

        # s4: h10(1), h11(2), h12(3), s3(4), s5(5)
        self.addLink(hosts['h10'], switches['s4'], port1=0, port2=1)
        self.addLink(hosts['h11'], switches['s4'], port1=0, port2=2)
        self.addLink(hosts['h12'], switches['s4'], port1=0, port2=3)

        # s5: h13(1), h14(2), h15(3), s4(4), s6(5)
        self.addLink(hosts['h13'], switches['s5'], port1=0, port2=1)
        self.addLink(hosts['h14'], switches['s5'], port1=0, port2=2)
        self.addLink(hosts['h15'], switches['s5'], port1=0, port2=3)

        # s6: h16(1), h17(2), h18(3), s5(4)
        self.addLink(hosts['h16'], switches['s6'], port1=0, port2=1)
        self.addLink(hosts['h17'], switches['s6'], port1=0, port2=2)
        self.addLink(hosts['h18'], switches['s6'], port1=0, port2=3)

        # Inter-switch links (tagged VLANs)
        self.addLink(switches['s1'], switches['s2'], port1=4, port2=4)
        self.addLink(switches['s2'], switches['s3'], port1=5, port2=4)
        self.addLink(switches['s3'], switches['s4'], port1=5, port2=4)
        self.addLink(switches['s4'], switches['s5'], port1=5, port2=4)
        self.addLink(switches['s5'], switches['s6'], port1=5, port2=4)


def setup_faucet_ovs():
    """Configure OVS switches for Faucet"""
    import subprocess

    for i in range(1, 7):
        switch = f's{i}'
        # Set OpenFlow 1.3
        subprocess.run(['ovs-vsctl', 'set', 'bridge', switch, 'protocols=OpenFlow13'], check=False)
        # Set datapath ID
        subprocess.run(['ovs-vsctl', 'set', 'bridge', switch, f'other-config:datapath-id=000000000000000{i}'], check=False)
        # Enable STP (optional)
        subprocess.run(['ovs-vsctl', 'set', 'bridge', switch, 'stp_enable=true'], check=False)


def run_topology(controller_ip='127.0.0.1', controller_port=6653):
    """Run the Mininet topology"""
    topo = DDoSTopo()

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )

    # Add remote controller (Faucet)
    c0 = net.addController('c0', controller=RemoteController,
                          ip=controller_ip, port=controller_port)

    info('*** Starting network\n')
    net.start()

    info('*** Configuring OVS for Faucet\n')
    setup_faucet_ovs()

    info('*** Waiting for switches to connect to Faucet\n')
    import time
    time.sleep(5)

    # Verify connectivity
    info('*** Testing connectivity\n')
    net.pingAll()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')

    # Allow custom controller IP/Port
    controller_ip = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    controller_port = int(sys.argv[2]) if len(sys.argv) > 2 else 6653

    run_topology(controller_ip, controller_port)