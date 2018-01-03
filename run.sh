# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
sudo rm sw_conf_large_v2.json
sudo rm logs/*
sudo rm capture/*
#sudo python topo/nsw_ip.py --behavioral-exe $TARGET --json $1
sudo  python $1 --num-host $2 --behavioral-exe $TARGET --json $3
