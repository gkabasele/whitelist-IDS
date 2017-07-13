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

from p4_mininet import P4Switch, P4Host
from config_switch import SwitchConf
from config_switch import SwitchCollection

import argparse
import os
from time import sleep

parser = argparse.ArgumentParser(description='Mininet demo')
parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=True)
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts by subnet',
                    type=int, action="store", default=1)
parser.add_argument('--num-subnet', help='Number of field site',
                    type=int, action="store",default=3)
parser.add_argument('--mode', choices=['l2', 'l3'], type=str, default='l3')
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=True)
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)

args = parser.parse_args()

# TODO TopologyDB to generate json file   
class MultiSwitchTopo(IPTopo):
    """Backbone is a ring of router each connected to a field site containing a P4
     Switch"""
    def build(self, *args, **kwargs):
        # Initialize topology and default options
        log_dir = "log/"

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
                                dpid = self.int2dpid(0))
       
        sw_conf = SwitchConf(dpid="0", 
                             real_ip = "10.0.10.10",
                             port = str(thrift_port),
                             resp_network = ["10.0.10.0/24"])
                             
        host = self.addHost('mtu',mac = '00:05:00:00:00:00', ip="10.0.10.1/24")
        self.addLink(host,sw_control)

        intf = str(sw_conf.current_intf)
        sw_conf.routing_table.append({"10.0.10.1/32":intf})
        sw_conf.arp_table.append({"10.0.10.1":"00:05:00:00:00:00"})
        sw_conf.add_interface({intf : "00:AA:BB:00:00:01"})

        router_cc = self.addRouter('rcc')

        self.addLink(router_cc , sw_control, igp_passive=True, params1={"ip":("10.0.10.30/24")})
        intf = str(sw_conf.current_intf)
        sw_conf.add_interface({intf : "00:AA:BB:CC:00:01"})
        sw_conf.ids_port = intf
        sw_conf.gw_port = intf

        encoder.add_switch_conf("0", sw_conf) 


        for i in xrange(n_sub):
            label_sw = "s%d"%(i+1)
            label_router = "r%d"%(i+1)
            enable_debug = True
            log = "logs/sw_%s.log" % (i+1)

            switches[(i+1)] = self.addSwitch(label_sw,
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port+(i+1),
                                dpid = self.int2dpid(i+1),
                                enable_debugger= enable_debug,
                                log_file = log)

            # Id start at 0 and ip at 1
            sw_confg =  SwitchConf(dpid=str(i+1), 
                             real_ip = "10.0.%d0.10" % (i + 2),
                             port = str(thrift_port + (i+1)),
                             resp_network = ["10.0.%d0.0/24"%(i + 2)])
            encoder.add_switch_conf((i+1), sw_confg)
                   
            routers[(i+1)] = self.addRouter(label_router) 

        ids_addr = None 
        for switch_id in switches:
            switch = switches[switch_id]
            router = routers[switch_id]
            ids_added = False
            sw_confg = encoder.get_switch_conf(switch_id)
            for h in xrange(n_host):
                mac = "00:04:00:00:%02x:%02x" %(switch_id,h)
                ip = "10.0.%d0.%d/24"%(switch_id+1 , h+1)
                intf_mac = "00:AA:BB:00:%02x:%02x" % (switch_id+1, h +1)
                if switch_id != 3 and not ids_added:
                    sw_conf.resp_network.append("10.0.%d0.0/24"% (switch_id+1))
                    host = self.addHost("s%d-h%d" % (switch_id, h + 1),
                                        mac = mac,
                                        ip = ip) 
                    ids_added = True
                    self.addLink(host, switch)

                    self.host_switch_conf(sw_confg, intf_mac, mac, ip)

                    if switch_id == 1:
                        ip = "10.0.%d0.%d/24"%(switch_id+1 , h+2)
                        mac =  "00:04:00:00:%02x:%02x" %(switch_id,h+1)
                        intf_mac = "00:AA:BB:00:%02x:%02x" % (switch_id+1, h +2)
                        host = self.addHost("s%d-h%d" % (switch_id, h + 2),
                                    mac = mac,
                                    ip = ip) 
                        self.addLink(host, switch)
                        self.host_switch_conf(sw_confg, intf_mac, mac, ip)
                        
                else:
                    ids = self.addHost("s%d-h%d" % (switch_id, h + 1),
                                    mac = mac,
                                    ip= ip)
                    root_gw = self.addHost("s%d-h%d"% (switch_id, h + 2),
                                            ip = "172.0.10.2/24", 
                                            inNamespace=False)
                    ids_addr = ip[:-3]
                    self.addLink(ids, switch)
                    self.host_switch_conf(sw_confg, intf_mac, mac, ip) 
                    self.addLink(ids, root_gw,  params1={"ip":("172.0.10.1/24")})

            self.addLink(router, switch, igp_passive=True, params1={"ip":("10.0.%d0.30/24"%(switch_id + 1))})
            self.router_switch_conf(sw_confg, "00:AA:BB:CC:%02x:01" %(switch_id +1))

        self.addLink('rcc', 'r1', igp_area = "0.0.0.0", params1={"ip":("10.0.100.1/24")},params2={"ip":("10.0.100.2/24")}) 
        self.addLink('r1', 'r2', igp_area = "0.0.0.0", params1={"ip":("10.0.101.1/24")},params2={"ip":("10.0.101.2/24")}) 
        self.addLink('r2', 'r3', igp_area = "0.0.0.0", params1={"ip":("10.0.102.1/24")},params2={"ip":("10.0.102.2/24")}) 
        self.addLink('r3', 'rcc', igp_area = "0.0.0.0", params1={"ip":("10.0.103.1/24")},params2={"ip":("10.0.103.2/24")}) 
        
        self.set_ids_addr(encoder, ids_addr)

        encoder.encode_switch_conf("sw_conf.json")
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

    kwargs =  {"sw_path" : args.behavioral_exe,
               "json_path" : args.json,
               "thrift_port" : args.thrift_port,
               "n_host": args.num_hosts,
               "n_sub": args.num_subnet}

    net = IPNet(topo = MultiSwitchTopo(**kwargs),
                host = P4Host,
                switch = P4Switch,
                ipBase='10.0.0.0/16',
                allocate_IPs = False,
                controller = None)
    net.start()
    
    #MTU connection    
    h =  net.get('mtu')
    sw_mac = "00:aa:bb:cc:dd:ee" 
    sw_addr ="10.0.10.10" 

    if mode == "l2":
        h.setDefaultRoute("dev eth0")
    else:
        print "Setting ARP entries for mtu"  
        print "%s\t%s"% (sw_addr, sw_mac)
        h.setARP(sw_mac, sw_addr)
        h.cmd("ip route add default dev eth0" )

    # Ingress and host connection
    for i in xrange(num_subnet):
        sub_id  = i+1
        sw = net.get('s%d'%sub_id)
        sw_mac = ["00:aa:bb:00:%02x:%02x" % (sub_id, n) for n in xrange(num_hosts)]

        sw_addr = ["10.0.%d0.%d0" % (sub_id + 1, n + 1) for n in xrange(num_hosts)]

        for n in xrange(num_hosts):
            h = net.get('s%d-h%d' % (sub_id, n + 1))
            if mode == "l2":
                h.setDefaultRoute("dev eth0")
            else:
                print "Setting ARP entries for s%d-%d" % (sub_id, n+1) 
                print "%s\t%s"% (sw_addr[n], sw_mac[n])
                h.setARP(sw_addr[n], sw_mac[n])
                h.cmd("ip route add default dev eth0" )

    h = net.get('mtu')
    h.describe()

    for i in xrange(num_subnet):
        sub_id = i+1
        for n in xrange(num_hosts):
            h = net.get('s%d-h%d' % (sub_id, n + 1))
            h.describe()
    h = net.get('s3-h1')
    h_gw = net.get('s3-h2')
    h_gw.cmd('ip link set s3-h2-eth0 up')  
    h.cmd('sudo iptables -I INPUT -i eth0 -j NFQUEUE --queue-num 1')
    sleep(1)
    
    #topodb = TopologyDB(net=net)
    #topodb.save("topo.json")
    print "Ready !"

    IPCLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
