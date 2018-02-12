# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
sudo rm sw_conf_large_v2.json
sudo rm logs/*
sudo rm capture/*
sudo p4c-bmv2 --json whitelist_v4.json code_p4/v3/ingress_switch.p4
#sudo python topo/nsw_ip.py --behavioral-exe $TARGET --json $1
sudo  python $1 --num-host $2 --behavioral-exe $TARGET --json $3
