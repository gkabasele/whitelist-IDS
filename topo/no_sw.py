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


# TODO TopologyDB to generate json file   
class MultiSwitchTopo(IPTopo):
    """Backbone is a ring of router each connected to a field site containing a P4
     Switch"""
    def build(self, *args, **kwargs):
        # Initialize topology and default options
        routers = {}
               
                                     
        host = self.addHost('mtu',mac = '00:05:00:00:00:00', ip="10.0.10.1/24")


        router_cc = self.addRouter('rcc')

        self.addLink(router_cc , host, igp_passive=True, params1={"ip":("10.0.10.30/24")})



        for i in xrange(3):
            label_sw = "s%d"%(i+1)
            label_router = "r%d"%(i+1)

            routers[(i+1)] = self.addRouter(label_router) 

        for switch_id in routers:
            router = routers[switch_id]
            for h in xrange(1):
                if switch_id != 3:
                    mac = "00:04:00:00:%02x:%02x" %(switch_id,h)
                    ip = "10.0.%d0.%d/24"%(switch_id+1 , h+1)
                    intf_mac = "00:AA:BB:00:%02x:%02x" % (switch_id+1, h +1)
                    host = self.addHost("s%d-h%d" % (switch_id, h + 1),
                                         mac = mac,
                                         ip = ip) 
                    self.addLink(router, host, igp_passive=True, params1={"ip":("10.0.%d0.30/24"%(switch_id + 1))})

                    if switch_id == 1:
                        ip = "10.0.%d0.%d/24"%(switch_id+1 , h+2)
                        mac =  "00:04:00:00:%02x:%02x" %(switch_id,h+1)
                        intf_mac = "00:AA:BB:00:%02x:%02x" % (switch_id+1, h +2)
                        host = self.addHost("s%d-h%d" % (switch_id, h + 2),
                                            mac = mac,
                                            ip = ip) 
                        self.addLink(router, host, igp_passive=True, params1={"ip":("10.0.%d0.30/24"%(switch_id + 1))})
                            
                else:
                    ids = self.addHost("s%d-h%d" % (switch_id, h + 1),
                                    mac = mac,
                                    ip= ip)
                    root_gw = self.addHost("s%d-h%d"% (switch_id, h + 2),
                                            ip = "172.0.10.2/24", 
                                            inNamespace=False)
                    ids_addr = ip[:-3]
                    self.addLink(router, ids, igp_passive=True, params1={"ip":("10.0.%d0.30/24"%(switch_id + 1))})
                    self.addLink(ids, root_gw,  params1={"ip":("172.0.10.1/24")})



        self.addLink('rcc', 'r1', igp_area = "0.0.0.0", params1={"ip":("10.0.100.1/24")},params2={"ip":("10.0.100.2/24")}) 
        self.addLink('r1', 'r2', igp_area = "0.0.0.0", params1={"ip":("10.0.101.1/24")},params2={"ip":("10.0.101.2/24")}) 
        self.addLink('r2', 'r3', igp_area = "0.0.0.0", params1={"ip":("10.0.102.1/24")},params2={"ip":("10.0.102.2/24")}) 
        self.addLink('r3', 'rcc', igp_area = "0.0.0.0", params1={"ip":("10.0.103.1/24")},params2={"ip":("10.0.103.2/24")}) 
        

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
    net = IPNet(topo = MultiSwitchTopo(),
                host = Host,
                switch = Switch,
                ipBase='10.0.0.0/16',
                allocate_IPs = False,
                controller = None)
    net.start()
    
    #MTU connection    
    h =  net.get('mtu')
    sw_mac = "00:aa:bb:cc:dd:ee" 
    sw_addr ="10.0.10.10" 

    print "Setting ARP entries for mtu"  
    print "%s\t%s"% (sw_addr, sw_mac)
    h.setARP(sw_mac, sw_addr)
    h.cmd("ip route add default dev eth0" )

    # Ingress and host connection
    for i in xrange(3):
        sub_id  = i+1
        sw_mac = ["00:aa:bb:00:%02x:%02x" % (sub_id, n) for n in xrange(3)]

        sw_addr = ["10.0.%d0.%d0" % (sub_id + 1, n + 1) for n in xrange(3)]

        for n in xrange(1):
            h = net.get('s%d-h%d' % (sub_id, n + 1))
            print "Setting ARP entries for s%d-%d" % (sub_id, n+1) 
            print "%s\t%s"% (sw_addr[n], sw_mac[n])
            h.setARP(sw_addr[n], sw_mac[n])
            h.cmd("ip route add default dev eth0" )

    h = net.get('mtu')
    #h.describe()

    for i in xrange(3):
        sub_id = i+1
        for n in xrange(1):
            h = net.get('s%d-h%d' % (sub_id, n + 1))
            #h.describe()
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
