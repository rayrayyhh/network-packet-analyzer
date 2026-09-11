from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_network():
	net = Mininet(
		controller = Controller,
		switch = OVSSwitch
	)

	net.addController("c0")

	h1 = net.addHost("h1", ip="10.0.0.1/24")
	h2 = net.addHost("h2", ip="10.0.0.2/24")
	h3 = net.addHost("h3", ip="10.0.0.3/24")

	s1 = net.addSwitch("s1")

	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s1)

	return net, h1, h2, h3