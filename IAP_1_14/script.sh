#!/bin/sh
#               IAP Assignment 1                 
#			BHUSHAN KULKARNI  12CS30016 
#			Gaurav Kumar      12CS10020
#			Ankit Kumar Gupta 12CS10006
                                                 
if [ $# -lt 2 ]; then
    echo "usage: $0 stp_enable true/false"
    exit -1;
fi


# create host
ip netns add h1
ip netns add h2

# confirm creation of hosts
ip netns show
#!/bin/sh
# create 3 switches
ovs-vsctl add-br s1
ovs-vsctl add-br s2
ovs-vsctl add-br s3

# confirm switch creation
ovs-vsctl show

# create link between a) host and switches b) two switches 
ip link add h1-eth0 type veth peer name s1-eth0
ip link add h2-eth0 type veth peer name s2-eth0
ip link add s1-eth1 type veth peer name s2-eth1
ip link add s1-eth2 type veth peer name s3-eth0
ip link add s2-eth2 type veth peer name s3-eth1



# confirm link creation
ip link show

# Move host ports into namespaces
ip link set h1-eth0 netns h1
ip link set h2-eth0 netns h2

# verify
ip netns exec h1 ip link show
ip netns exec h2 ip link show

# connect switch port to OVS
ovs-vsctl add-port s1 s1-eth0
ovs-vsctl add-port s1 s1-eth1
ovs-vsctl add-port s1 s1-eth2
ovs-vsctl add-port s2 s2-eth0
ovs-vsctl add-port s2 s2-eth1
ovs-vsctl add-port s2 s2-eth2
ovs-vsctl add-port s3 s3-eth0
ovs-vsctl add-port s3 s3-eth1

# confirm

ovs-vsctl show

# Set up OpenFlow controller
ovs-vsctl set-controller s1 tcp:127.0.0.1
ovs-vsctl set-controller s2 tcp:127.0.0.1
ovs-vsctl set-controller s3 tcp:127.0.0.1

# Assigning IP addresses to interfaces and turning on the interfaces
ip netns exec h1 ifconfig h1-eth0 10.0.10.1
ip netns exec h1 ifconfig lo up
ip netns exec h2 ifconfig h2-eth0 10.0.10.2
ip netns exec h2 ifconfig lo up
ifconfig s1-eth0 up
ifconfig s1-eth1 up
ifconfig s1-eth2 up
ifconfig s2-eth0 up
ifconfig s2-eth1 up
ifconfig s2-eth2 up
ifconfig s3-eth0 up
ifconfig s3-eth1 up

# echo $2;
# enable STP support 
ovs-vsctl set Bridge s1 stp_enable=$2
ovs-vsctl set Bridge s2 stp_enable=$2
ovs-vsctl set Bridge s3 stp_enable=$2

# enable STP support
# ovs-vsctl set Bridge s1 stp_enable=false
# ovs-vsctl set Bridge s2 stp_enable=false
# ovs-vsctl set Bridge s3 stp_enable=false

# start server client
# ip netns exec h1 ./server.o 10.0.10.1 10000 &
# ip netns exec h2 ./client.o 10.0.10.1 10000 &

