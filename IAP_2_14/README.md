# to start the Controller run
cd source/pox
sudo ./pox.py log.level --DEBUG pox.misc.clb


sudo mn --custom ./source/topology.py --topo=mytopo --controller=remote,ip=127.0.0.1,port=6633

