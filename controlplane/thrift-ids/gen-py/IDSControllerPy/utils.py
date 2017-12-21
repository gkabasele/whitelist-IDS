from scapy.all import *
import struct
import socket
import ssl
import cPickle as pickle
import sys
import json
from P4Constants import *
from netaddr import IPNetwork
from netaddr import IPAddress


class SRTag(Packet):
    name = "SRTag"
    fields_desc=[ IPField("dst", None),
                  ShortField("identifier", None),
                  ByteField("protocol", None),
                  ByteField("reason", None)
                ]
 
class Modbus(Packet):
    name = "Modbus"
    fields_desc=[ ShortField("transactionID", 0),
                  ShortField("protocolID", 0),
                  ShortField("length", None),
                  ByteField("unitID", 0),
                  ByteField("funcode", None)
                ]

class ModbusDiag(Packet):
    name = "ModbusDiag"
    fields_desc=[ ShortField("subfuncode",None)]

class Switch():
    '''
        sw_id : Id of the switch
        ip_address: IP address used by the thrift server
        port : port used by thrift server
        resp : list of address that the switch handles
        interface: list of interface the switch has (name:mac)
        ids_port: outport on the switch to reach the IDS
        gw_port : outport on the switch to reach gateway
        ids_addr: ip address of IDS
        routing_table : dest ip : port
        arp_table : arp table for entry in subnet work
        p4_table : matching table
    '''
    def __init__(self, 
                 sw_id,
                 ip_addr,
                 real_ip,
                 port,
                 resp,
                 interfaces,
                 ids_port,
                 gw_port,
                 ids_addr,
                 routing_table,
                 arp_table):

        self.sw_id = sw_id
        self.ip_address = IPNetwork(ip_addr)
        self.real_ip = real_ip
        self.port = port
        self.resp = []
        for network in resp:
            ip_network = IPNetwork(network)
            self.resp.append(ip_network)
        self.interfaces = interfaces
        self.ids_port = ids_port
        self.gw_port = gw_port
        self.ids_addr = ids_addr
        self.routing_table = routing_table
        self.arp_table = arp_table
        # Current entry number in each important table
        self.p4_table = {FLOW_ID : 0 , MODBUS : 0, BLOCK_HOSTS : 0}

    def is_responsible(self,ip_addr):
        r = False
        ip = IPAddress(ip_addr)
        for subnet in self.resp:
            if ip in subnet:
                r = True
                break
        return r

'''
    -Creates the switches from a json file containing their configuration
'''
def create_switches(filename):

    json_data=open(filename)
    topo = json.load(json_data)
    switches = []
    for sw in topo['switches']:
        sw_id = sw['dpid']
        ip_addr = sw['ip_address']
        real_ip = sw['real_ip']
        port = sw['port']
        resp = sw['resp_network']
        routing_table = sw['routing_table']
        arp_table = sw['arp_table']
        ids_port = sw['ids_port']
        gw_port = sw['gw_port']
        interfaces = sw['interfaces']
        ids_addr = sw['ids_addr']
        
    
        switch = Switch(sw_id, 
                        ip_addr,
                        real_ip,
                        port, 
                        resp,
                        interfaces,
                        ids_port, 
                        gw_port,
                        ids_addr,
                        routing_table,
                        arp_table)
        switches.append(switch)
    
    json_data.close() 
    return switches


