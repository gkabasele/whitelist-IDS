# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
sudo rm sw_conf.json
sudo rm logs/*
#sudo python topo/nsw_ip.py --behavioral-exe $TARGET --json config-json/whitelist.json
#sudo python topo/nsw_ip.py --behavioral-exe $TARGET --json config-json/whitelist_v2.json
sudo python topo/nsw_ip.py --behavioral-exe $TARGET --json $1
