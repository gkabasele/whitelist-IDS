# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
sudo rm sw_conf.json
sudo rm logs/switch.log.txt
sudo python topo/ids_topo.py --behavioral-exe $TARGET --json config-json/whitelist.json
