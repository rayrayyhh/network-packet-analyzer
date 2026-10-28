"""A three-host LAN; the standalone OVS bridge needs no controller process."""
from mininet.net import Mininet
from mininet.node import OVSBridge


def create_network():
    net = Mininet(controller=None, switch=OVSBridge)
    h1 = net.addHost("h1", ip="10.0.0.1/24")
    h2 = net.addHost("h2", ip="10.0.0.2/24")
    h3 = net.addHost("h3", ip="10.0.0.3/24")
    switch = net.addSwitch("s1")
    for port, host in enumerate((h1, h2, h3), start=1):
        net.addLink(host, switch, port2=port)
    return net, h1, h2, h3
