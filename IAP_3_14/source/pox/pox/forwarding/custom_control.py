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
from threading import Thread
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp,unreach,echo
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import *
from pox.lib.recoco import Timer
import time
import networkx as nx
import sys

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0
HELLOINT = 5
NBRTIMEOUT = 15
LSUINT = 30
LSUTIMEOUT = 90
_hello_tos = 126
_lsu_tos = 127

class LearningSwitch (object):
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
    self.G=nx.DiGraph()
    self.hosts=[]
    self.times = {}
    self.def_int = 2
    self.ct=1
    self.times2 = {}
    self.seqnum = {}
    self.seq=1
    self.neighbours = {}
    self.arp_table={}
    self.subnet_mask='255.255.255.0'
    global HELLOINT
    # Assign IP and Eth Address
    if(self.connection.dpid==1): # Router R1
      self.IPAddr=IPAddr('10.0.1.1')
      self.EthAddr=EthAddr('00:00:00:00:00:01')
      self.hosts.append('10.0.1.2')
      self.hosts.append('10.0.1.3')
      self.G.add_edge(IPAddr('10.0.1.1'),IPAddr('10.0.1.2'))
      self.G.add_edge(IPAddr('10.0.1.1'),IPAddr('10.0.1.3'))
    elif(self.connection.dpid==2): # Router R2
      self.IPAddr=IPAddr('10.0.2.1')
      self.EthAddr=EthAddr('00:00:00:00:00:02')
      self.hosts.append('10.0.2.2')
      self.G.add_edge(IPAddr('10.0.2.1'),IPAddr('10.0.2.2'))
    elif(self.connection.dpid==3): # Router R3
      self.IPAddr=IPAddr('10.0.3.1')
      self.EthAddr=EthAddr('00:00:00:00:00:03')
      self.hosts.append('10.0.3.2')
      self.G.add_edge(IPAddr('10.0.3.1'),IPAddr('10.0.3.2'))
      self.def_int=3
    else:
      self.IPAddr=IPAddr('10.0.4.1')        # Router R4
      self.EthAddr=EthAddr('00:00:00:00:00:04')
      self.hosts.append('10.0.4.2')
      self.hosts.append('10.0.4.3')
      self.G.add_edge(IPAddr('10.0.4.1'),IPAddr('10.0.4.2'))
      self.G.add_edge(IPAddr('10.0.4.1'),IPAddr('10.0.4.3'))
    self.que=[]

    # Thread(target=self._handle_timer,args=()).start()
    Timer( HELLOINT, self._handle_timer, recurring=True)
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
      for tpl in self.que:
      	eth=tpl[0]
      	Interface=tpl[1]
      	prt=tpl[2]
        if eth.payload.dstip==packet.next.protosrc:
          eth.dst=packet.src
          msg = of.ofp_packet_out()
          msg.data = eth.pack()
          # print "inport",of.OFPP_IN_PORT
          # print "outport",int(Interface)
          msg.actions.append(of.ofp_action_output(port = int(Interface)))
          msg.in_port = prt
          self.connection.send(msg)
        else:
          que1.append(tpl)
      self.que=que1

  def handle_icmp(self,event):
    print "ICMP Packet Arrived"
    packet=event.parsed
    src_mac = packet.src
    dst_mac = packet.dst
    ipv4_packet = event.parsed.find("ipv4")
    src_ip = ipv4_packet.srcip
    dst_ip = ipv4_packet.dstip

    if packet.payload.next.type==8:
		print "handing"
		icmp_rep = icmp()
		# icmp_rep.type = 3
		icmp_rep.next=echo()
		icmp_rep.next.seq=packet.payload.next.next.seq
		icmp_rep.next.id=packet.payload.next.next.id
		icmp_rep.next.raw=packet.payload.next.next.raw

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
		msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
		msg.in_port = event.port
		self.connection.send(msg)
		print "done handing"
		return

    if packet.payload.next.type==3:
      if packet.payload.next.type==1:
        print "Destination Host Unreachable"
      if packet.payload.next.type==0:
        print "Destination Network Unreachable"
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
    ip=IPAddr(ip)
    if self.ComputeNetWorkAddr(ip.toStr(),self.subnet_mask)==self.ComputeNetWorkAddr(self.IPAddr.toStr(),self.subnet_mask):
    	if ip.toStr() in self.hosts:
    		return ip.toStr(),str(self.def_int),0
    	else :
    		return -1,-1,1
    if ip not in self.G.nodes():
    	ip1=ip.toStr().split('.')
    	ip1[-1]='1'
    	ip1='.'.join(ip1)
    	if IPAddr(ip1) not in self.G.nodes():
    		return -1,-1,0
    	else:
    		ip=IPAddr(ip1)
    if not nx.has_path(self.G,self.IPAddr,ip):
    	return -1,-1,0
    l=nx.shortest_path(self.G,self.IPAddr,ip)
    for x in l:
      sys.stderr.write(x.toStr()+"\n")
    sys.stderr.write("self.G\n")
    for e in self.G.edges():
      sys.stderr.write(e[0].toStr()+" "+e[1].toStr()+"\n\n")
    for i in self.neighbours.keys():
      if self.neighbours[i]==l[1]:
      	return l[1].toStr(),str(i),0
    return -1,-1,0
  			
  def isValidIpPacket(self,event):
    ipv4_packet = event.parsed.find("ipv4")
    if(ipv4_packet.csum!=ipv4_packet.checksum()):
  	  print "Ip packet checksum not macthing"
  	  return False
    if(ipv4_packet.ttl<=0):
      print "TTL Invalid"
      icmp_rep = icmp()
      icmp_rep.type = 11 # TYPE_TIME_EXCEED
      #icmp_rep.code=0
      icmp_rep.next=unreach()

      # icmp_rep.next.seq=packet.payload.next.next.seq
      # icmp_rep.next.id=packet.payload.next.next.id
      # icmp_rep.next.raw=packet.payload.next.next.raw

      # Show the client that it's actually the me
      rep=ipv4()
      rep.srcip=self.IPAddr
      rep.dstip=ipv4_packet.srcip
      rep.next=icmp_rep
      rep.protocol=ipv4_packet.payload.ICMP_PROTOCOL
      eth = ethernet()
      eth.dst = ipv4_packet.src
      eth.src = self.EthAddr
      eth.set_payload(rep)
      eth.type = ethernet.IP_TYPE
      msg = of.ofp_packet_out()
      msg.data = eth.pack()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
      msg.in_port = event.port
      self.connection.send(msg)
      return False		
    if(ipv4_packet.iplen<20):
  	  print "Length Invalid"
  	  return False	
    # len > min_len
    return True

  def handle_ipPacket(self,event): # handle broad cast ip also 
    # print "IP packet Received at R"+str(event.dpid)

    packet=event.parsed
    if(packet is None):
    	print "error"
    	print event
    src_mac = packet.src
    dst_mac = packet.dst

    ipv4_packet = event.parsed.next
    if(ipv4_packet is None):
      print "error"
      print event
    # Do more processing of the IPv4 packet
    src_ip = ipv4_packet.srcip
    dst_ip = ipv4_packet.dstip
    global _hello_tos, _lsu_tos
    if ipv4_packet.tos == _hello_tos:
      print "HELLO at R"+str(event.dpid)+" from "+src_ip.toStr()
      self.neighbours[event.port]=src_ip
      sys.stderr.write(self.IPAddr.toStr()+" "+str(event.port)+" "+src_ip.toStr()+"\n")
      self.times[event.port]=time.time()
      self.G.add_edge(self.IPAddr,src_ip)
      self.send_lsu()
      return

    if ipv4_packet.tos == _lsu_tos:
      if src_ip==self.IPAddr:
        return
      print "LSU at R"+str(event.dpid)+" from "+src_ip.toStr()
      self.times2[src_ip]=time.time()
      pl=ipv4_packet.next
      lst=pl.split(':')[:-1]
      if src_ip in self.seqnum.keys() and self.seqnum[src_ip]>=int(pl[0]):
      	return
      self.seqnum[src_ip]=int(pl[0])
      try:
        self.G.remove_node(src_ip)
      except:
        pass
      for i in lst[1:]:
      	self.G.add_edge(src_ip,IPAddr(i))
      eth = ethernet()
      eth.src = self.EthAddr
      eth.set_payload(ipv4_packet)
      eth.type = ethernet.IP_TYPE
      msg = of.ofp_packet_out()
      msg.data = eth.pack()
      msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
      self.connection.send(msg)
      return

    if dst_mac!=self.EthAddr and dst_mac!=EthAddr('ff:ff:ff:ff:ff:ff'):
      return
    
    if(not self.isValidIpPacket(event)):
      return

    if(dst_ip==self.IPAddr or dst_ip.toStr()=='255.255.255.255'):
      if(packet.payload.protocol==packet.payload.ICMP_PROTOCOL):
      	self.handle_icmp(event)
    else:   
      nxt=self.FindNextHopInterface(dst_ip.toStr())
      if(nxt[0]==-1):   # need to send an icmp packet 
        # print "No Route to Host"
        # Create ARP reply
        icmp_rep = icmp()
        icmp_rep.type = 3
        icmp_rep.code= nxt[2]
        icmp_rep.next=unreach()

        # icmp_rep.next.seq=packet.payload.next.next.seq
        # icmp_rep.next.id=packet.payload.next.next.id
        # icmp_rep.next.raw=packet.payload.next.next.raw

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
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port
        self.connection.send(msg)
        print "icmp reply DONE"

      else:
        NextHopIP=nxt[0]
        Interface=nxt[1][-1]

        payload=packet.payload.payload # payload of IP packet
        # create a empty IP packet

        ipv4_packet_out=ipv4_packet
        ipv4_packet_out.ttl=ipv4_packet_out.ttl-1
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
          msg.actions.append(of.ofp_action_output(port = int(Interface)))
          msg.in_port = event.port
          self.connection.send(msg)
        else:
          arp_rep = arp()
          arp_rep.opcode = arp.REQUEST

          # Show the client that it's actually the me
          arp_rep.hwsrc = self.EthAddr
          arp_rep.hwdst = EthAddr('ff:ff:ff:ff:ff:ff')
          #arp_rep.hwdst = 'ff:ff:ff:ff:ff:ff'
          arp_rep.protosrc = self.IPAddr
          arp_rep.protodst = IPAddr(NextHopIP)

          # Create the Ethernet packet
          eth1 = ethernet()
          eth1.type = ethernet.ARP_TYPE
          eth1.dst = EthAddr('ff:ff:ff:ff:ff:ff')
          eth1.src = self.EthAddr
          eth1.set_payload(arp_rep)

          # Send the ARP reply to client
          # msg is the "packet out" message. Now giving this packet special properties
          msg = of.ofp_packet_out()
          msg.data = eth1.pack()
          msg.actions.append(of.ofp_action_output(port = int(Interface)))
          msg.in_port = event.port
          self.connection.send(msg)
          eth.src = self.EthAddr
          eth.set_payload(ipv4_packet_out)
          self.que.append((eth,int(Interface),event.port))
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

  def send_lsu(self):
	  pl=str(self.seq)+':'
	  self.seq=self.seq+1
	  for i in self.neighbours.values():
	  	pl=pl+i.toStr()+':'
	  for i in self.hosts:
	  	pl=pl+i+':'
	  rep=ipv4()
	  rep.next=pl
	  global _lsu_tos
	  rep.tos=_lsu_tos
	  rep.srcip=self.IPAddr
	  eth = ethernet()
	  eth.src = self.EthAddr
	  eth.set_payload(rep)
	  eth.type = ethernet.IP_TYPE
	  msg = of.ofp_packet_out()
	  msg.data = eth.pack()
	  msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
	  self.connection.send(msg)

  def _handle_timer(self):
  	  # print "sending IP packet from R"+str(self.connection.dpid) 
    rep=ipv4()
    global _hello_tos
    if self.ct==6:
    	self.send_lsu()
    	self.ct=0
    self.ct=self.ct+1
    rep.tos=_hello_tos
    rep.srcip=self.IPAddr;
    eth = ethernet()
    eth.src = self.EthAddr;
    eth.set_payload(rep)
    eth.type = ethernet.IP_TYPE
    msg = of.ofp_packet_out()
    msg.data = eth.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
    self.connection.send(msg)

    # CHECK outdated self.neighbours
    tm=time.time()
    sz=self.times.keys()
    global NBRTIMEOUT,LSUTIMEOUT
    for port in sz:
      if tm-self.times[port]>NBRTIMEOUT:
        sys.stderr.write(str(tm-self.times[port])+" REMOVED "+neighbours[port].toStr()+"\n")
        self.times.pop(port,0)
        self.G.remove_node(neighbours[port])
        self.neighbours.pop(port,0)

    for ip in self.times2.keys():
      if tm-self.times2[ip]>LSUTIMEOUT and self.G.has_node(ip):
          self.G.remove_node(ip)
          sys.stderr.write(str(tm-self.times2[ip])+" REMOVED "+ip.toStr()+"\n")
    if len(self.times.keys())<len(sz):
    	self.send_lsu()
    # print "sending IP packet done from R"+str(self.connection.dpid)	


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
