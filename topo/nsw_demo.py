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

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from p4_mininet import P4Switch, P4Host

import argparse
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


class MultiSwitchTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, n, n_sub, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switches = {}

        sw_control = self.addSwitch('cc',
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port,
                                pcap_dump = pcap_dump,
                                dpid = self.int2dpid(0))
        host = self.addHost('mtu',
                              ip = "10.0.10.1/24",
                              mac = '00:05:00:00:00:00' )
        self.addLink(host,sw_control)

        for i in xrange(n_sub):
            label = "s%d"%(i+1)
            switches[(i+1)] = self.addSwitch(label,
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port+(i+1),
                                pcap_dump = pcap_dump,
                                dpid = self.int2dpid(i+1))
            
        for switch_id in switches:
            switch = switches[switch_id]
            for h in xrange(n):
                host = self.addHost('s%d-h%d' % (switch_id, h + 1),
                                ip = "10.0.%s0.%d/24" % (switch_id + 1, h + 1),
                                mac = '00:04:00:00:%02x:%02x' %(switch_id,h))
                self.addLink(host, switch)
            self.addLink(switch,sw_control)

    def int2dpid( self, dpid ):
        try:
            dpid = hex( dpid )[ 2: ]
            dpid = '0' *( 16  - len( dpid ) ) + dpid
            return dpid
        except IndexError:
            raise Exception ( 'dpid error' )


def main():
    num_hosts = args.num_hosts
    num_subnet = args.num_subnet
    mode = args.mode

    topo = MultiSwitchTopo(args.behavioral_exe,
                            args.json,
                            args.thrift_port,
                            args.pcap_dump,
                            num_hosts,
                            num_subnet)
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4Switch,
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
        h.setDefaultRoute("dev eth0 via %s" % sw_addr)

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
                h.setDefaultRoute("dev eth0 via %s" % sw_addr[n])

    h = net.get('mtu')
    h.describe()

    for i in xrange(num_subnet):
        sub_id = i+1
        for n in xrange(num_hosts):
            h = net.get('s%d-h%d' % (sub_id, n + 1))
            h.describe()

    sleep(1)

    print "Ready !"

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
