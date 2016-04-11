#!/bin/sh
#               IAP Assignment 2                
#			BHUSHAN KULKARNI  12CS30016 
#			Gaurav Kumar      12CS10020
#			Ankit Kumar Gupta 12CS10006
# echo "start"
cd source/pox
# echo "folder"
sudo ./pox.py log.level --WARNING pox.forwarding.custom_control > log.txt &
# echo "here1"
cd ../..
sudo mn --custom ./source/topology.py --topo=mytopo --controller=remote,ip=127.0.0.1,port=6633
# echo "here2"
