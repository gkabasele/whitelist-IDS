# !/bin/bash

TARGET=~/p4-tutorials/bmv2/targets/simple_switch/simple_switch
SWFILE=whitelist_v4.json
sudo rm sw_conf_large_v2.json
sudo rm logs/*
sudo rm capture/*
sudo p4c-bmv2 --json whitelist_v4.json code_p4/v3/ingress_switch.p4

sudo mn -c > /dev/null

if sudo pgrep -x "bro" > /dev/null
then
   sudo pkill "bro"
fi 

POSITIONAL=()
while [[ $# -gt 0 ]] 
do
key="$1"

case $key in
    -t|--topo=*)
    TOPO="$2"
    shift # past argument=value
    shift
    ;;
    -n|--num=*)
    NUM="--num-host $2"
    shift # past argument=value
    shift
    ;;
    -v|--var=*)
    VAR="--varfile $2"
    shift
    shift
    ;;
    -i|--iter=*)
    ITER="--nb_iter $2"
    shift
    shift
    ;;
    -s|--strat=*)
    STRAT="--strategy $2"
    shift
    shift
    ;;
    -a|--auto=*)
    AUTO="--auto"
    shift
    ;;
    -m|--malicious=*)
    MALICIOUS="--malicious"
    shift
    ;;
    --default)
    DEFAULT=YES
    shift
    ;;
    *)
    POSITIONAL+=("$1")
    shift
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

#echo "sudo python ${TOPO} ${NUM} --behavioral-exe $TARGET --json $SWFILE ${STRAT} ${VAR} ${AUTO} ${MALICIOUS} ${ITER}"
sudo python ${TOPO} ${NUM} --behavioral-exe $TARGET --json $SWFILE ${STRAT} ${VAR} ${AUTO} ${MALICIOUS} ${ITER}
#if [ $? -eq 0 ] 
#then
#    if [ "$#" -le 3 ] 
#    then
#        sudo python $1 --num-host $2 --behavioral-exe $TARGET --json whitelist_v4.json 
#    elif [ "$#" -le 4 ] 
#    then
#        sudo  python $1 --num-host $2 --auto --strategy $3 --behavioral-exe $TARGET --json whitelist_v4.json
#    else 
#        sudo python $1 --num-host $2 --auto --strategy $3 --attack  --behavioral-exe $TARGET --json whitelist_v4.json
#    fi
#fi
