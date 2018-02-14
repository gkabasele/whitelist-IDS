# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
sudo rm sw_conf_large_v2.json
sudo rm logs/*
sudo rm capture/*
sudo p4c-bmv2 --json whitelist_v4.json code_p4/v3/ingress_switch.p4
if [ $? -eq 0 ]; then
    if [ "$#" -le 3 ]; then
        sudo python $1 --num-host $2 --behavioral-exe $TARGET --json whitelist_v4.json 
    else
        sudo  python $1 --num-host $2 --auto $3 --behavioral-exe $TARGET --json whitelist_v4.json
    fi
fi
