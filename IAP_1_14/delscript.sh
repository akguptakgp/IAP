#!/bin/sh
# delete
ip netns del h1
ip netns del h2

# delete
ovs-vsctl del-br s1
ovs-vsctl del-br s2
ovs-vsctl del-br s3

# delete
ip link delete h1-eth0 
ip link delete s1-eth0
ip link delete h2-eth0 
ip link delete s2-eth0
ip link delete s1-eth1
ip link delete  s2-eth1
ip link delete s1-eth2 
ip link delete s3-eth0
ip link delete s2-eth2
ip link delete s3-eth1

# remove controller
ovs-vsctl del-controller s1 
ovs-vsctl del-controller s2 
ovs-vsctl del-controller s3 