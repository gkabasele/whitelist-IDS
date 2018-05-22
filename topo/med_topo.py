#!/usr/bin/env python2

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from ipmininet.ipnet import IPNet
from ipmininet.iptopo import IPTopo
from ipmininet.topologydb import TopologyDB
from mininet.log import setLogLevel, info
from ipmininet.cli import IPCLI
from mininet.node import Switch, Host
from ipmininet.link import IPLink, TCIntf
from p4_mininet import P4Switch, P4Host
from config_switch import SwitchConf
from config_switch import SwitchCollection

import argparse
import os
import sys
import shutil
import threading
from time import sleep


parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts by subnet',
                    type=int, action="store", default=1)
parser.add_argument('--num-subnet', help='Number of field site',
                    type=int, action="store", default=3)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on ifaces to pcap files',
                    type=str, action="store", required=False, default=False)

### Read config file ?

parser.add_argument('--auto', help='Automatically run command', default=False,
                    action='store_true')
parser.add_argument('--attack', help='start attack', default=False,
                    action='store_true')
parser.add_argument('--phys_name', help='Physical process name', type=str,
                    default='medium-process')
parser.add_argument('--nb_iter', help='Number of iteration for the process',
                    type=str, default=60, action='store')
parser.add_argument('--strategy', help='Strategy used by the IDS',
                    choice=['critical', 'normal'], default='critical')
parser.add_argument('--varfile', help='Physical process description',
                    type=str, default='requirements.yml')
args = parser.parse_args()

cur_dir = os.getcwd()
phys_name = cur_dir + '/physical_process/' + args.phys_name
sys.path.append(phys_name)

import medium_process
import store_watcher
from constants import *


store = phys_name + '/' + STORE
export_dir = phys_name + '/' + EXPORT_VAR
plc_log_dir = phys_name + '/' + PLCS_LOG

# TODO TopologyDB to generate json file   
class MultiSwitchTopo(IPTopo):
    """Backbone is a ring of router each connected to a field site containing a P4
     Switch"""
    def build(self, *args, **kwargs):
        # Initialize topology and default options
        log_dir = "logs/"

        sw_path = kwargs.get('sw_path')
        json_path = kwargs.get('json_path')
        thrift_port = kwargs.get('thrift_port')
        n_host = kwargs.get('n_host')
        n_sub = kwargs.get('n_sub')


        switches = {}
        routers = {}
        encoder = SwitchCollection()
        sw_control = self.addSwitch('cc',
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port,
                                dpid = self.int2dpid(0),
                                enable_debugger = True,
                                log_file = log_dir+"cc" )
       
        sw_conf = SwitchConf(dpid="0", 
                             real_ip = "10.0.10.10",
                             port = str(thrift_port),
                             resp_network = ["10.0.10.0/24"])
                             
        host = self.addHost('mtu',mac = '00:05:00:00:00:00', ip="10.0.10.1/24")
        self.addLink(host,sw_control, intf=TCIntf, params1={"delay":"5ms", "bw":10}, params2={"delay":"5ms", "bw":10})

        intf = str(sw_conf.current_intf)
        sw_conf.routing_table.append({"10.0.10.1/32":intf})
        sw_conf.arp_table.append({"10.0.10.1":"00:05:00:00:00:00"})
        sw_conf.add_interface({intf : "00:AA:BB:00:00:01"})

        router_cc = self.addRouter('rcc')

        self.addLink(router_cc , sw_control, intf=TCIntf, igp_passive=True, params1={"ip":("10.0.10.30/24"), "delay":"5ms", "bw":10}, params2={"delay":"5ms", "bw":10})
        intf = str(sw_conf.current_intf)
        sw_conf.add_interface({intf : "00:AA:BB:CC:00:01"})
        sw_conf.ids_port = intf
        sw_conf.gw_port = intf

        encoder.add_switch_conf("0", sw_conf)

        #Field Site and Core network (wan) creation
        for i in xrange(n_sub):
            label_sw = "s%d"%(i+1)
            label_router = "r%d"%(i+1)
            enable_debug = True
            log = log_dir+"sw_%s.log" % (i+1)

            switches[(i+1)] = self.addSwitch(label_sw,
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port+(i+1),
                                dpid = self.int2dpid(i+1),
                                enable_debugger= enable_debug,
                                log_file = log)

            # Id start at 0 and ip at 1
            sw_confg =  SwitchConf(dpid=str(i+1), 
                             real_ip = "10.0.%d0.%d5" % ((i + 2),(i +2)),
                             port = str(thrift_port + (i+1)),
                             resp_network = ["10.0.%d0.0/24"%(i + 2)])
            encoder.add_switch_conf((i+1), sw_confg)
                   
            routers[(i+1)] = self.addRouter(label_router) 

        ids_addr = "10.0.40.1" 
        #ids_addr = None 
        num_ids = 0
        for switch_id in switches:
            switch = switches[switch_id]
            router = routers[switch_id]
            sw_confg = encoder.get_switch_conf(switch_id)
            for h in xrange(n_host):
                if num_ids < 1:
                    mac = "00:04:00:00:%02x:%02x" %(switch_id,h)
                    ip = "10.0.%d0.%d/24"%(switch_id+1 , h+1)
                    # intefarce of the switch
                    intf_mac = "00:AA:BB:00:%02x:%02x" % (switch_id+1, h +1)
                    sw_conf.resp_network.append("10.0.%d0.0/24"% (switch_id+1))
                    host = self.addHost("s%d-h%d" % (switch_id, h + 1),
                                        mac = mac,
                                        ip = ip) 
                    self.addLink(host, switch, intf=TCIntf,params1={"delay":"5ms", "bw":10},params2={"delay":"5ms", "bw":10})

                    self.host_switch_conf(sw_confg, intf_mac, mac, ip)
                    if switch_id == 3:
                        num_ids +=1

                if switch_id == 3 and num_ids==1:
                    root_gw = self.addHost("s%d-h%d"% (switch_id, h + 2),
                                            ip = "172.0.10.2/24", 
                                            inNamespace=False)
                    #ids_addr = ip[:-3]
                    self.addLink(host, root_gw,  params1={"ip":("172.0.10.1/24")})
                    num_ids += 1

            self.addLink(router, switch, intf=TCIntf,igp_passive=True,params1={"ip":("10.0.%d0.30/24"%(switch_id + 1)), "delay":"5ms","bw":10}, params2={"delay":"5ms","bw":10})
            self.router_switch_conf(sw_confg, "00:AA:BB:CC:%02x:01" %(switch_id +1))

        self.addLink('rcc', 'r1', intf=TCIntf,igp_area = "0.0.0.0", params1={"ip":("10.0.100.1/24"),"delay":"5ms", "bw":10},params2={"ip":("10.0.100.2/24"), "delay":"5ms", "bw":10}) 
        self.addLink('r1', 'r2', intf=TCIntf,igp_area = "0.0.0.0", params1={"ip":("10.0.101.1/24"),"delay":"5ms", "bw":10},params2={"ip":("10.0.101.2/24"), "delay":"5ms", "bw":10}) 
        self.addLink('r2', 'r3', intf=TCIntf, igp_area = "0.0.0.0", params1={"ip":("10.0.102.1/24"),"delay":"5ms", "bw":10},params2={"ip":("10.0.102.2/24"), "delay":"5ms", "bw":10}) 
        self.addLink('r3', 'rcc', intf=TCIntf, igp_area = "0.0.0.0", params1={"ip":("10.0.103.1/24"),"delay":"5ms", "bw":10},params2={"ip":("10.0.103.2/24"), "delay":"5ms", "bw":10}) 
        self.addLink('r3', 'r1', intf=TCIntf,igp_area = "0.0.0.0", params1={"ip":("10.0.105.1/24"),"delay":"5ms", "bw":10},params2={"ip":("10.0.105.2/24"), "delay":"5ms", "bw":10}) 
        
        self.set_ids_addr(encoder, ids_addr)

        encoder.encode_switch_conf("sw_conf_large_v2.json")
        super(MultiSwitchTopo, self).build(*args, **kwargs)

    def int2dpid( self, dpid ):
        try:
            dpid = hex( dpid )[ 2: ]
            dpid = '0' *( 16  - len( dpid ) ) + dpid
            return dpid
        except IndexError:
            raise Exception ( 'dpid error' )

    def host_switch_conf(self, sw_conf, intf_mac, mac, ip):
        intf = str(sw_conf.current_intf)
        sw_conf.routing_table.append({ip.replace("/24","/32") :intf})
        sw_conf.arp_table.append({ip[:-3]:mac})
        sw_conf.add_interface({intf : intf_mac})

    def router_switch_conf(self, sw_conf, mac):
        intf = str(sw_conf.current_intf)
        sw_conf.add_interface({intf : mac})
        sw_conf.ids_port = intf
        sw_conf.gw_port = intf

    def set_ids_addr(self, col, ids_addr):
        for sw_conf in col.switches_conf.values():
            sw_conf.ids_addr = ids_addr

def main():

    num_hosts = args.num_hosts
    num_subnet = args.num_subnet
    mode = args.mode
    auto = args.auto
    strategy = args.strategy
    varfile = args.varfile

    kwargs =  {"sw_path" : args.behavioral_exe,
               "json_path" : args.json,
               "thrift_port" : args.thrift_port,
               "n_host": args.num_hosts,
               "n_sub": args.num_subnet}

    net = IPNet(topo=MultiSwitchTopo(**kwargs),
                host=P4Host,
                switch=P4Switch,
                ipBase='10.0.0.0/16',
                use_v6 =False,
                allocate_IPs=False,
                controller=None,
                link=IPLink,
                intf=TCIntf)
    net.start()

    #MTU connection    
    mtu = net.get('mtu')
    sw_mac = "00:aa:bb:cc:dd:ee"
    sw_addr ="10.0.10.15"

    if mode == "l2":
        mtu.setDefaultRoute("dev eth0")
    else:
        print "Setting ARP entries for mtu"
        print "%s\t%s"% (sw_addr, sw_mac)
        mtu.setARP(sw_mac, sw_addr)
        mtu.cmd("ip route add default dev eth0")

    mtu.describe()

    # Ingress and host connection
    for i in xrange(num_subnet):
        sub_id = i+1
        sw = net.get('s%d'%sub_id)
        sw_mac = ["00:aa:bb:00:%02x:%02x" % (sub_id, sub_id) for n in xrange(num_hosts)]

        sw_addr = ["10.0.%d0.%d5" % (sub_id + 1, sub_id + 1) for n in xrange(num_hosts)]

        sw.cmd("tcpdump -i s%d-eth1 -w " % (sub_id)  + cur_dir + "/capture/s%s.pcap&" % (sub_id) )
        for n in xrange(num_hosts):
            try:
                h = net.get('s%d-h%d' % (sub_id, n + 1))
                ip = "10.0.%d0.30" % (sub_id + 1)
                mac = "00:00:00:00:00:01"
                if mode == "l2":
                    h.setDefaultRoute("dev eth0")
                else:
                    print "Setting ARP entries for s%d-%d" % (sub_id, n+1) 
                    print "%s\t%s"% (sw_addr[n], sw_mac[n])
                    print "%s\t%s"% (ip,mac) 
                    h.setARP(sw_addr[n], sw_mac[n])
                    h.setARP(ip,mac)
                    h.cmd("ip route add default dev eth0" )
            except KeyError:
                "Warning: Could not find host s%d-h%d"% (sub_id, n +1)
    
    modbus_servers = []

    if args.auto:
        if os.path.exists(store):
            shutil.rmtree(store)
        os.mkdir(store)
        
        if os.path.exists(export_dir):
            shutil.rmtree(export_dir)
        os.mkdir(export_dir)

        if os.path.exists(plc_log_dir):
            shutil.rmtree(plc_log_dir)
        os.mkdir(plc_log_dir)

    t = None
    if auto:
        t = threading.Thread(name='process', target= store_watcher.start, args=(store, args.nb_iter))
        print "Starting physical process"
        t.start()

    variable_process = os.listdir(phys_name + '/plcs')

    for i in xrange(num_subnet):
        sub_id = i+1
        for n in xrange(num_hosts):
            if sub_id == 1:
                name = 's%d-h%d' % (sub_id, n +1)
                h = net.get(name)
                h.describe()
                ip = "10.0.%d0.%d" % ((sub_id + 1), (n + 1))
                modbus_servers.append(ip)
                if auto:
                    print "Starting PLC %s" % (variable_process[n])
                    mod = 'python '+ phys_name +"/plcs/" + variable_process[n] + ' --ip 10.0.%d0.%d --port 5020 --store %s --duration %s --export %s --create --period %s&' % ((sub_id + 1), (n+1), store, DURATION, export_dir, PLC_PERIOD )
                    print mod
                    capt = 'tcpdump -i eth0 -w ' + cur_dir + '/capture/' + name + '.pcap&' 
                    output = h.cmd(mod)
                    #h.cmd(capt)

    ids = net.get('s3-h1')
    ids.describe()
    ctrl = net.get('s3-h2')
    ctrl.describe()
    ctrl.cmd('ip link set s3-h2-eth0 up')  
    if auto:
        ids.cmd('tcpdump -i eth0 -w' + cur_dir + '/capture/' + 'ids.pcap&')
    ids.cmd('sudo iptables -I INPUT -i eth0 -j NFQUEUE --queue-num 2')
    ids.cmd('sudo iptables -I FORWARD -i eth0 -j NFQUEUE --queue-num 1')
    ids.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Enable iptable for Force Listen Mode simulation
    #h = net.get('s2-h1')
    #h.cmd('sudo iptables -I INPUT -i eth0 -j NFQUEUE --queue-num 1')
    # Disabling reverse path filter
    for i in ['rcc','r1','r2','r3']:
        r = net.get(i)
        for name in r.nameToIntf:
            print name
            if 'eth0' in name:
                command = "ifconfig %s down" %name
                r.cmd(command)
                command = "ifconfig %s hw ether 00:00:00:00:00:01" %name
                r.cmd(command)
                command = "ifconfig %s up" % name
                r.cmd(command)
            command = "sysctl -w net.ipv4.conf.%s.rp_filter=0" % name
            r.cmd(command)
        if i != 'rcc':
            for h in xrange(num_hosts):
                print "Setting ARP entries for %s" % i 
                mac = "00:04:00:00:%02x:%02x" %(int(i[-1]),h)
                ip = "10.0.%d0.%d"%(int(i[-1]) + 1 , h+1)
                print "%s\t%s"% (ip,mac) 
                r.setARP(ip,mac)

        #r.cmd("tcpdump -i %s-eth0 -w " % (i)  + cur_dir + "/capture/%s.pcap&" % (i) )
        r.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
        r.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")
    r = net.get('r3')
    # Log packet whose destination ar not suppose to arrive
    r.cmd('echo 1 >/proc/sys/net/ipv4/conf/r3-eth0/log_martians')
    sleep(1)
    
    # Run the controller
    if auto:
        print "Starting Controller"
        comd = "python " + cur_dir + "/controlplane/thrift-ids/gen-py/IDSControllerPy/controller.py --conf " + cur_dir +"/sw_conf_large_v2.json --desc " + phys_name + "/" + varfile
        output = ctrl.cmd(comd)
        comd = "tcpdump -i s3-h2-eth0 -w " + cur_dir + "/capture/controlplane.pcap&"
        ctrl.cmd(comd)
        sleep(1)
        # Run Bro
        print "Starting Bro"
        comd = "cd " + cur_dir + "/bro_setup && bro -b -C -i eth0 server_broker.bro&"
        ids.cmd(comd)
        sleep(2)
        # Run IDS
        print "Starting Intrusion Detection System"
        comd = cur_dir +"/controlplane/thrift-ids/gen-cpp/controller_client -c " + cur_dir + "/ids.cfg&"
        ids.cmd(comd)
        comd = "python " + cur_dir +"/spec_ids/gen-py/IDSControllerPy/ids.py --varfile " + phys_name + "/" + varfile + " --strategy " + strategy
        ids.cmd(comd)
        sleep(1)

        # Run Modbus Client
        print "Starting Master Terminal Unit"
        comd = "python " + phys_name + "/script_mtu.py --ip 10.0.10.1 --port 3000 --duration %s --import %s&" % (DURATION, export_dir)
        mtu.cmd(comd)
        mtu.cmd("tcpdump -i eth0 -w " + cur_dir + "/capture/mtu.pcap tcp&") 
        
        if args.attack:

            # Attacker machine
            print "Starting Attack Machine"
            attack_machine = net.get("s2-h1")
            comd = "python " + phys_name + "/script_attack.py --ip 10.0.30.1 --port 4000 --duration %s --import %s --period 0.5 &" % (DURATION, export_dir)
            attack_machine.cmd(comd)
            attack_machine.cmd("tcpdump -i eth0 -w " + cur_dir + "/capture/attack.pcap tcp&")

    print "Ready !"

    IPCLI( net )
    net.stop()
    if t is not None:
        t.join()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
