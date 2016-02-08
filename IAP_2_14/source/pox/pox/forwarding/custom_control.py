# Copyright 2011-2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An L2 learning switch.
It is derived from one written live for an SDN crash course.
It is somwhat similar to NOX's pyswitch in that it installs
exact-match rules for each flow.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp,unreach,echo
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import *

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class LearningSwitch (object):
  """
  The learning switch "brain" associated with a single OpenFlow switch.
  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.
  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.
  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).
  In short, our algorithm looks like this:
  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """

    packet = event.parsed

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)

class LearningRouter (object):
  def __init__ (self, connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.arp_table={}
    # Assign IP and Eth Address
    if(self.connection.dpid==1): # Router R1
      self.IPAddr=IPAddr('10.0.1.1')
      self.EthAddr=EthAddr('00:00:00:00:00:01')
      # self.arp_table[IPAddr('10.0.1.2')]=EthAddr('00:00:00:00:00:01')
      # self.arp_table[IPAddr('10.0.1.3')]=EthAddr('00:00:00:00:00:01')
    elif(self.connection.dpid==2): # Router R2
      self.IPAddr=IPAddr('10.0.2.1')
      self.EthAddr=EthAddr('00:00:00:00:00:02')
      # self.arp_table[IPAddr('10.0.2.2')]=EthAddr('00:00:00:00:00:01')
    elif(self.connection.dpid==3): # Router R3
      self.IPAddr=IPAddr('10.0.3.1')
      self.EthAddr=EthAddr('00:00:00:00:00:03')
      # self.arp_table[IPAddr('10.0.3.2')]=EthAddr('00:00:00:00:00:01')
    else:
      self.IPAddr=IPAddr('10.0.4.1')        # Router R4
      self.EthAddr=EthAddr('00:00:00:00:00:04')
      # self.arp_table[IPAddr('10.0.4.2')]=EthAddr('00:00:00:00:00:01')
      # self.arp_table[IPAddr('10.0.4.3')]=EthAddr('00:00:00:00:00:01')
    
    self.arp_table[IPAddr('10.0.1.1')]=EthAddr('00:00:00:00:00:01')
    self.arp_table[IPAddr('10.0.2.1')]=EthAddr('00:00:00:00:00:02')
    self.arp_table[IPAddr('10.0.3.1')]=EthAddr('00:00:00:00:00:03')
    self.arp_table[IPAddr('10.0.4.1')]=EthAddr('00:00:00:00:00:04')

    self.que=[]


    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)
  
  def handle_arp (self, packet, in_port):
    print "ARP Packet Arrived at Router R"+str(self.connection.dpid)+" at Interface"+str(in_port)
    
    if packet.payload.opcode == arp.REQUEST:
      arp_req = packet.next

      # Create ARP reply
      arp_rep = arp()
      arp_rep.opcode = arp.REPLY

      # Show the client that it's actually the me
      arp_rep.hwsrc = self.EthAddr
      arp_rep.hwdst = arp_req.hwsrc
      arp_rep.protosrc = self.IPAddr
      arp_rep.protodst = arp_req.protosrc

      # Create the Ethernet packet
      eth = ethernet()
      eth.type = ethernet.ARP_TYPE
      eth.dst = packet.src
      eth.src = self.EthAddr
      eth.set_payload(arp_rep)

      # Send the ARP reply to client
      # msg is the "packet out" message. Now giving this packet special properties
      msg = of.ofp_packet_out()
      msg.data = eth.pack()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      msg.in_port = in_port
      self.connection.send(msg)
      print "arp reply DONE"

    if packet.payload.opcode == arp.REPLY:
      self.arp_table[packet.next.protosrc]=packet.src
      que1=[]
      for eth in que:
        if eth.payload.dstip==packet.next.protosrc:
          eth.dst=packet.src
          msg = of.ofp_packet_out()
          msg.data = eth.pack()
          # print "inport",of.OFPP_IN_PORT
          # print "outport",int(Interface)
          msg.actions.append(of.ofp_action_output(port = int(Interface)))
          msg.in_port = event.port
          self.connection.send(msg)
        else:
          que1.append(eth)
      que=que1

  def handle_icmp(self,event):
    print "ICMP Packet Arrived"
    packet=event.parsed
    if packet.payload.next.type==3:
      print "Destination Host Unreachable"
    return
  
  def ComputeNetWorkAddr(self,Ip,netMask):
    ip=Ip.split('.')
    net=netMask.split('.')
    Netstr=''
    for i in range(len(ip)):
      Netstr=Netstr+str(int(ip[i])&int(net[i]))
      Netstr=Netstr+'.'
    return Netstr[:-1]  

  def FindNextHopInterface(self,ip):
    f=open('../route_tabels/r'+str(self.connection.dpid)+'_tabel.txt')
    if(f!=None):
      route=f.read().split('\n')[1:]
      longestMatch=-1
      indx=-1
      longestMatchIndx=-1
      for f in route:
        destIp=f.split()[0]
        netMask=f.split()[1]
        indx+=1
        if(destIp==self.ComputeNetWorkAddr(ip,netMask)):
          if(longestMatch < netmask_to_cidr(netMask)):
            longestMatchIndx=indx
            longestMatch=netmask_to_cidr(netMask)
            nextHop=f.split()[2]
            Interface=f.split()[3]
            # print "longestMatchIndx",longestMatch,indx
      # print longestMatchIndx,longestMatch
      if(longestMatchIndx==-1):
        return (longestMatchIndx,longestMatchIndx)
      return nextHop,Interface
        # print "netmask_to_cidr",nextHop,Interface
  def isValidIpPacket(self,packet):
    # ttl>0 
    # len > min_len
    return True

  def handle_ipPacket(self,event): # handle broad cast ip also 
    print "IP packet Received at R"+str(event.dpid)
    packet=event.parsed
      # return
    src_mac = packet.src
    dst_mac = packet.dst
    # print src_mac
    # print dst_mac
    if dst_mac!=self.EthAddr and dst_mac!=EthAddr('ff:ff:ff:ff:ff:ff'):
      return
    
    if(not self.isValidIpPacket(packet)):
      return

    if(packet.payload.protocol==packet.payload.ICMP_PROTOCOL):
      self.handle_icmp(event)

    ipv4_packet = event.parsed.find("ipv4")
    # Do more processing of the IPv4 packet
    src_ip = ipv4_packet.srcip
    dst_ip = ipv4_packet.dstip
    # print src_ip.toStr()
    # print dst_ip.toStr()
    # print ipv4_packet

    if(dst_ip==self.IPAddr or dst_ip.toStr()=='255.255.255.255'):
      print "My Packet accept at ",self.IPAddr
      print ipv4_packet
    else:   
      nxt=self.FindNextHopInterface(dst_ip.toStr())
      if(nxt[0]==-1):   # need to send an icmp packet 
        print "No Route to Host"
        # Create ARP reply
        icmp_rep = icmp()
        icmp_rep.type = 3

        # Show the client that it's actually the me
        rep=ipv4()
        rep.srcip=self.IPAddr
        rep.dstip=src_ip
        rep.next=icmp_rep
        rep.protocol=packet.payload.ICMP_PROTOCOL
        eth = ethernet()
        eth.dst = packet.src
        eth.src = self.EthAddr
        eth.set_payload(rep)
        eth.type = ethernet.IP_TYPE
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port = int(Interface)))
        msg.in_port = event.port
        self.connection.send(msg)
        print "icmp reply DONE"

      else:
        NextHopIP=nxt[0]
        Interface=nxt[1][-1]
        # print "send to ",NextHopIP," using Interface",int(Interface)
        
        ## Assuming we have ARP need to implement
        # print "Next Hop MAc",self.arp_table[IPAddr(NextHopIP)]

        payload=packet.payload.payload # payload of IP packet
        # create a empty IP packet

        ipv4_packet_out=ipv4_packet
        ipv4_packet_out.ttl=ipv4_packet_out.ttl-1
        # print "copied",ipv4_packet_out
        # print "origin",ipv4_packet_out

        # Create the Ethernet packet

        eth = ethernet()
        eth.type = ethernet.IP_TYPE
        if IPAddr(NextHopIP) in self.arp_table: 
          eth.dst = self.arp_table[IPAddr(NextHopIP)]
          eth.src = self.EthAddr
          eth.set_payload(ipv4_packet_out)

          # msg is the "packet out" message. Now giving this packet special properties
          msg = of.ofp_packet_out()
          msg.data = eth.pack()
          # print "inport",of.OFPP_IN_PORT
          # print "outport",int(Interface)
          msg.actions.append(of.ofp_action_output(port = int(Interface)))
          msg.in_port = event.port
          self.connection.send(msg)
        else:
          arp_rep = arp()
          arp_rep.opcode = arp.REQUEST

          # Show the client that it's actually the me
          arp_rep.hwsrc = self.EthAddr
          #arp_rep.hwdst = 'ff:ff:ff:ff:ff:ff'
          arp_rep.protosrc = self.IPAddr
          arp_rep.protodst = IPAddr(NextHopIP)

          # Create the Ethernet packet
          eth1 = ethernet()
          eth1.type = ethernet.ARP_TYPE
          eth1.dst = 'ff:ff:ff:ff:ff:ff'
          eth1.src = self.EthAddr
          eth1.set_payload(arp_rep)

          # Send the ARP reply to client
          # msg is the "packet out" message. Now giving this packet special properties
          msg = of.ofp_packet_out()
          msg.data = eth1.pack()
          msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
          msg.in_port = in_port
          self.connection.send(msg)
          eth.src = self.EthAddr
          eth.set_payload(ipv4_packet_out)
          que.append(eth)
           #  eth.dst = EthAddr('ff:ff:ff:ff:ff:ff')
        

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    
    if packet.type==packet.IP_TYPE or packet.type==packet.ARP_TYPE: # only handle ARP and IP packet
      if packet.type == packet.ARP_TYPE:
        # Handle ARP request for load balancer

        # Only accept ARP request for MY router
        # since I am  the gateway router I can simply ignore if ARP in not destined to me
        if packet.next.protodst != self.IPAddr:
         return 
        log.debug("Receive an ARP Packet")
        self.handle_arp(packet, event.port)

      elif packet.type == packet.IP_TYPE:
        log.debug("Receive an IP Packet")
        self.handle_ipPacket(event) 
    else: 
      # Drop packets
      # send of command without actions
      msg = of.ofp_packet_out()
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)
      # print "packet droped"
      return

class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    # print "new gfgj"
    core.openflow.addListeners(self)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    print "Switch %s has come up." % event.dpid
    # print dpidToStr(event.dpid)
    if(event.dpid==5 or event.dpid==6):
      LearningSwitch(event.connection, self.transparent)
    else:
      LearningRouter(event.connection)
      pass
      # print "ignoring switch",event.dpid  


def launch (transparent=False, hold_down=_flood_delay):
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))
