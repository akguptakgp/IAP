## run all this commands from main directory [current directory]
## to create the topology
## first delete any existing bridges and namespaces using the following commands 
sudo bash
./delscript.sh  x
## ignore any error if get in the above command
## then run
./script.sh stp_enable true # for running with stp enabled
./script.sh stp_enable false # for running with stp disabled

## now our topology has been created 
## to attach udp server at h1 run 
ip netns exec h1 ./server.o 10.0.10.1 10000

## to attach udp client at h2 open a new terminal run
sudo bash
ip netns exec h2 ./client.o 10.0.10.1 10000

## now you can see echo udp packet getting transmitted


## packets can be captured using
wireshark

## there are two folders with contains the wireshark traces at each interface