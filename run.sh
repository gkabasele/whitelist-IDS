# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
sudo rm sw_conf.json
sudo rm logs/sw_*
sudo python topo/nsw_ip.py --behavioral-exe $TARGET --json config-json/whitelist.json
