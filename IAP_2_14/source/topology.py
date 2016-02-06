"""Custom topology example
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self)
        # self.addController('c0',controller=RemoteController,ip="127.0.0.1",port=6633)
        # Add hosts and switches
        # info( '*** Add hosts\n')
        h1 = self.addHost('h1', cls=Host, ip='10.0.1.2/24', defaultRoute=None)
        h2 = self.addHost('h2', cls=Host, ip='10.0.1.3/24', defaultRoute=None)
        h4 = self.addHost('h4', cls=Host, ip='10.0.2.2/24', defaultRoute=None)
        h3 = self.addHost('h3', cls=Host, ip='10.0.3.2/24', defaultRoute=None)
        h5 = self.addHost('h5', cls=Host, ip='10.0.4.2/24', defaultRoute=None)
        h6 = self.addHost('h6', cls=Host, ip='10.0.4.3/24', defaultRoute=None)

        # info( '*** Add switches\n')
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch)
        R3 = self.addSwitch('R3', cls=OVSKernelSwitch)
        R2 = self.addSwitch('R2', cls=OVSKernelSwitch)
        R1 = self.addSwitch('R1', cls=OVSKernelSwitch)
        s2 = self.addSwitch('s2', cls=OVSKernelSwitch)
        R4 = self.addSwitch('R4', cls=OVSKernelSwitch)
        # print R1,'fgggggggggg'
        # print self.get('R1')
        # .cmd('ifconfig R1-eth0 10.0.1.1')
        # R2.cmd('ifconfig R2-eth0 10.0.2.1')
        # R3.cmd('ifconfig R3-eth0 10.0.3.1')
        # R4.cmd('ifconfig R4-eth0 10.0.4.1')

        # info( '*** Add links\n')
        self.addLink(h1, s1)
        self.addLink(s1, h2)

        self.addLink(R1, R3)
        self.addLink(s1, R1)
        self.addLink(R2, R1)

        self.addLink(R3, R4)

        self.addLink(R2, h4)

        self.addLink(h3, R3)
        
        self.addLink(s2, R4)

        self.addLink(s2, h5)
        self.addLink(s2, h6)

        self.addLink(R2, R4)



topos = { 'mytopo': ( lambda: MyTopo() ) }