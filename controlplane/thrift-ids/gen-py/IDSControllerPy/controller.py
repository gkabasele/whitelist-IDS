import os
import sys
import struct
import json
import cPickle as pickle
import inspect
import socket
import ssl
from netaddr import IPNetwork
from netaddr import IPAddress
from scapy.all import *

from Controller import Iface, Processor
from ttypes import *
from constants import*

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

from utils import *
from P4SwitchCom import *
import argparse

from functools import wraps
import  bmpy_utils as utils

from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *
try:
    from bm_runtime.simple_pre import SimplePre
except:
    pass
try:
    from bm_runtime.simple_pre_lag import SimplePreLAG
except:
    pass

import logging

logging.basicConfig(level=logging.DEBUG)

def verify(func):
    def wrapper(self, *args, **kwargs):
        a = list(args)
        assert len(a[0]) == self.num_fields, "Number of fields for the rule does not match"
        return func(self, *args)
    return wrapper

class RuleTables():
    '''
        rule : fields used for matching, ex :5-tuples (srcip, sport, dstip, dport, proto)
        resp_switch : list of switch concerned by this rule
        num_entry : dict {switch_id : num_entry} where entry is the id of the rule in
                  the table
    '''

    def __init__(self, num_fields) :
        self.rules = {}
        self.num_fields = num_fields 

    ''' 
        rule : fields used for matching
        switch_id : datapath id of switch containing the flow
        num_entry : number entry of flow in the flow table on the switch
        rule_type: ALLOW rule or DROP (for now, later REDIRECT,CLONED,...)
        wl_orig: Was the rule in the original whitelist

        Add rule to the table
    '''
    @verify
    def add_rule(self, rule, switch_id, num_entry, rule_type, wl_orig=False):
        if rule not in self.rules:
            self.rules[rule] = {switch_id : (num_entry,rule_type, wl_orig)}
        elif switch_id not in self.rules[rule]:
            self.rules[rule][switch_id] = (num_entry, rule_type, wl_orig)
    '''
        rule : fields used for matching
        switch_id : datapath id of switch containing the flow

        delete rule in the table
    '''

    @verify
    def delete_rule(self, rule, switch_id):
        self.rules[rule].pop(switch_id, None)
        if len(self.rules[rule]) == 0:
            self.rules.pop(rule,None)

    '''
        rule : fields used for matching
        switch_id : datapath id of switch containing the flow
        
        update rule entry number from the table
    '''
    @verify
    def update_rule(self, rule, switch_id, num_entry, rule_type):
        wl_orig = self.get_origin_entry(rule, switch_id) 
        self.rules[rule][switch_id] = (num_entry, rule_type, wl_orig)
        
    '''
        rule : fields used for matching
        
        return the list of switchs containing a rule for this fields
    '''
    @verify
    def rule_to_switches(self, rule):
        if rule in self.rules:
            return self.rules[rule].keys()

    '''
        rule : fields used for matching
        return the entry number of the rule in switch with switch_id
    '''
    @verify
    def get_num_entry(self, rule, switch_id):
        if rule in self.rules and switch_id in self.rules[rule]:
            return self.rules[rule][switch_id][0]
    '''
        rule : fields used for matching
        return the type (ALLOW,DROP) the rule in switch with switch_id
    '''
    @verify
    def get_type_entry(self, rule, switch_id):
        return self.rules[rule][switch_id][1]

    @verify
    def get_origin_entry(self, rule, switch_id):
        return self.rules[rule][switch_id][2]

    @verify
    def is_rule_installed(self, rule):
        return rule in self.rules

    def get_rules(self):
        return self.rules

    def dump_table(self):
        print "---------"
        print "RuleTable"
        for rule, sw in self.rules.iteritems():
            print rule,":"
            for sw_id, entry_handle in sw.iteritems():
                print "\tSwitch_id: ",sw_id," Entry: ",entry_handle , "\n"
        print "---------" 
bind_layers(TCP, Modbus, dport=5020)
bind_layers(TCP, Modbus, sport=5020)

IP_PROTO_TCP = 6
IP_PROTO_SRTAG = '200' 
IP_PROTO_IDSTAG = '201'
# Table name
SEND_FRAME = 'send_frame'
FORWARD = 'forward'
IPV4_LPM = 'ipv4_lpm'
FLOW_ID = 'flow_id'
MODBUS = 'modbus'
MISS_TAG= 'miss_tag_table'
ARP_RESP = 'arp_response'
ARP_FORW_REQ = 'arp_forward_req'
ARP_FORW_RESP = 'arp_forward_resp'
PKT_CLONED = 'pkt_cloned'
TCP_FLAGS = 'tcp_flags'
SRTAG = 'srtag_tab'
IDSTAG = 'idstag_tab'
IDSTAG_ADD_TAB = 'add_tag_ids_tab'
BLOCK_HOSTS = 'block_hosts'

# Action name
DROP = '_drop'
NO_OP = '_no_op'
ADD_TAG = 'add_miss_tag'
REMOVE_TAG = 'remove_miss_tag'
REWRITE = 'rewrite_mac'
DMAC = 'set_dmac'
SET_EGRESS = 'set_egress_port'
ADD_PORT = 'add_expected_port'
RESP = 'respond_arp'
STORE_ARP = 'store_arp_in'
FORWARD_ARP = 'forward_arp'
CLONE_I2E = '_clone_i2e'
REMOVE_IDSTAG = 'remove_ids_tag'
ADD_IDSTAG = 'add_ids_tag'


# Value name
CLONE_PKT_FLAG = '1'
MAX_BLOCK_REQUESTS = 3
RULE_ALLOW = 1
RULE_DROP = 0
RULE_ORIGINAL = True


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

class Controller(Iface):


    @staticmethod
    def get_thrift_services(pre_type):
        services = [("standard", Standard.Client)]

        if pre_type == PreType.SimplePre:
            services += [("simple_pre",SimplePre.Client)]
        elif pre_type == PreType.SimplePreLAG:
            services += [("simple_pre_lag", SimplePreLAG.Client)]
        else:
            services += [(None, None)]

        return services

    def __init__(self):
        self.clients = {}
        self.switches = {}
        self.ids_tag = {}
        self.ids_sw_id = None
        # Flow : srcip, sport, proto, dstip, dport
        self.flow_table = RuleTables(5)
        # Modbus : srcip, sport, funcode, payload_length
        self.modbus_table = RuleTables(4)
        # Blocked host : srcip, proto, dstip, dport
        self.block_hosts_table = RuleTables(4)
        # Number of block request received for a host
        self.block_request_host = {} 
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def add_client(self, id_client, standard_client, switch):
        self.clients[id_client] = standard_client
        self.switches[id_client] = switch


    def setup_connection(self, switches):
        once = True
        for sw in switches:
            standard_client, mc_client = thrift_connect(
                str(sw.ip_address.ip), int(sw.port), Controller.get_thrift_services(PreType.SimplePre)
            ) 
            # Loading config only once

            if once:
                load_json_config(standard_client)
                once = False
            self.add_client(sw.sw_id, standard_client, sw)  
    
    def checkreq(func):
        def wrapper(self, *args, **kwargs):
            a = list(args)
            if a[0] == None:
                err = IDSControllerException(1, "Invalid Request")
                raise err 
            else:
                return func(self, *args)
        return wrapper

    
    # Retrieve value from request
    def retrieve_value(self, req):
        # convert to unsigned 
        u_sport = (req.srcport & 0xffff)
        u_dport = (req.dstport & 0xffff)
        u_proto = (req.proto & 0xff)
        #Convert to string
        proto = str(u_proto)
        sport = str(u_sport)
        dport = str(u_dport)
        funcode = None
        length = None
        if req.funcode != None and req.length != None:
            u_funcode = (req.funcode & 0xff)
            u_length  = (req.length & 0xff)
            # Only accept non exception code and valid length
            if u_funcode > 127 and u_length < 3 :
                err = IDSControllerException(1, "Invalid Funcode or payload length")    
                raise err
            else:
                funcode = str(u_funcode)
                length = str(u_length)
        return (req.srcip, sport, proto, req.dstip, dport, funcode, length)

    def retrieve_nonce(self, sw):
        nonce = 0
        blocks = list(map(lambda x: (x & 0xffff), sw))
        for i, val in enumerate(blocks):
            nonce += (val << i*16) 
        return nonce
    # Forward packet but send clone to ids
    @checkreq
    def mirror(self, req, sw):
        pass

    # change the nonce when the IDS reforward the original packet
    @checkreq
    def redirect(self, req, blocks):
        resp = self.retrieve_value(req) 
        if len(resp) != 7:
            err = IDSControllerException(2, "redirect: Could not retrieve value from request")
            raise err
        if len(blocks) != 4:
            err = IDSControllerException(3, "redirect: Could not retrieve nonce")
            raise err
        nonce = self.retrieve_nonce(blocks)
        (srcip, sport, proto, dstip, dport, funcode, length) = resp

        print "\n--------------------------"
        print "Received Redirecting request" 
        print "srcip: %s, sport: %s, proto: %s" % (srcip, sport, proto)
        print "dstip: %s, dport: %s" % (dstip, dport)
        print "funcode: %s, length: %s" % (funcode, length)
        print "Nonce: %s" % nonce
        print "--------------------------\n" 

        
        # 1) Remove IDS tag from the switch connected to the IDS 
        # 2) Install IDS tag from the switch connected to the IDS 
        client = self.clients[self.ids_sw_id] 
        self.table_modify_entry(client, IDSTAG_ADD_TAB, ADD_IDSTAG, 0, [str(nonce)])

        # 3) Remove IDS tag from corresponding switches
        # 4) Install IDS tag from corresponding switches
        resp_sw = self.get_resp_switch(srcip, dstip)
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            # need to install a new rule for the switch
            entry_handle = self.table_add_entry(client, IDSTAG, REMOVE_IDSTAG , [IP_PROTO_IDSTAG, str(nonce), sw.ids_port], [])
            # Last argument set to 100ms
            self.table_set_entry_timeout(client, IDSTAG, entry_handle, 100)

    def is_flow_origin(self, flow):
        (srcip, sport, proto, dstip, dport) = flow
        origin = False
        for rule in self.flow_table.get_rules():
            (srcip_o, sport_o, proto_o, dstip_o, dport_o) = rule 
            # is there a flow from this host to that server in the original whitelist
            if (srcip_o == srcip and proto == proto_o and dstip_o == dstip and dport_o == dport):
                for sw_id in self.flow_table.rule_to_switches(rule):
                    origin = self.flow_table.get_origin_entry(rule, sw_id) 
                    if origin:
                        return origin
        return origin
        
    # Block flow
    @checkreq
    def block(self, req, sw):
        resp = self.retrieve_value(req)
        if len(resp) != 7:
            err = IDSControllerException(2, "block: Could not retrieve value from request")
            raise err
        (srcip, sport, proto, dstip, dport, funcode, length) = resp
        flow = (srcip, sport, proto, dstip, dport)

        print "\n--------------------------"
        print "Received Blocking request" 
        print "srcip: %s, sport: %s, proto: %s" % (srcip, sport, proto)
        print "dstip: %s, dport: %s" % (dstip, dport)
        print "funcode: %s, length: %s" % (funcode, length)
        print "--------------------------\n" 
        
        self.flow_table.dump_table()
        if ((dstip in self.block_request_host and
            self.block_request_host[dstip] >= MAX_BLOCK_REQUESTS) and
            not self.is_flow_origin((dstip, dport, proto, srcip, sport))):

            print "Blocking host %s for service %s\n" % (dstip, sport)

            #installed = self.is_flow_installed(flow)
            resp_sw = self.get_resp_switch(req.srcip, req.dstip)
            #  The source is the modbus server and we want to block the other endpoint
            self.deploy_block_host_rules(resp_sw, dstip, proto ,srcip, sport, self.add_block_entry ,RULE_DROP )  
        elif dstip in self.block_request_host:
            self.block_request_host[dstip] += 1
        else:
            self.block_request_host[dstip] = 1

    #TODO verify if switch in req same as the one in responsible switch
    
    # install flow in the whitelist
    @checkreq
    def allow(self, req, sw):
        resp = self.retrieve_value(req) 
        if len(resp) != 7 :
            err = IDSControllerException(2, "allow: Could not retrive value from request") 
            raise err
        
        (srcip, sport, proto, dstip, dport, funcode, length) = resp
        flow = (srcip, sport, proto, dstip, dport)
        print "\n-----------------------"
        print "Received Allowing request"
        print "srcip: %s, sport: %s, proto: %s" % (srcip, sport, proto)
        print "dstip: %s, dport: %s" % (dstip, dport)
        print "funcode: %s, length: %s" % (funcode, length)
        print "-------------------------\n" 
        installed = self.is_flow_installed(flow)
        
        resp_sw = self.get_resp_switch(req.srcip, req.dstip)
        self.deploy_flow_id_rules(resp_sw, srcip, sport, proto, dstip, dport, self.add_flow_id_entry, RULE_ALLOW)

        if installed and (funcode != None and length != None): 
            if not self.modbus_table.is_rule_installed((srcip, sport, funcode, length)):
                resp_sw = self.flow_table.rule_to_switches((srcip, sport, proto, dstip, dport))
                self.deploy_modbus_rules(resp_sw, srcip, sport, funcode, length, self.add_modbus_entry, RULE_ALLOW)  
        # Clear block request when new flow ?

    # Delete flow from the whitelist    
    @checkreq
    def remove(self, req, sw):
        resp = self.retrieve_value(req)
        if len(resp) != 7:
            err = IDSControllerException(2, "remove: Could not retrieve value from request")
            raise err
        (srcip, sport, proto, dstip, dport, funcode, length) = resp
        print "\n------------------------" 
        print " Received Removing request"
        print "srcip: %s, sport: %s, proto: %s" % (srcip, sport, proto)
        print "dstip: %s, dport: %s" % (dstip, dport)
        print "--------------------------\n" 
        if self.is_flow_installed((srcip, sport, proto, dstip, dport)):
            resp_sw = self.get_resp_switch(srcip, dstip)
            for sw in resp_sw:
                client = self.clients[sw.sw_id]
                entry_handle = self.flow_table.get_num_entry((srcip, sport, proto, dstip, dport), sw.sw_id)
                self.table_delete_entry(client, FLOW_ID, entry_handle)
                self.flow_table.delete_rule((srcip, sport, proto, dstip, dport), sw.sw_id)
        else:
            err = IDSControllerException(3, "remove: Try to remove uninstalled flow") 
            raise err

        
    def get_res(self, type_name, name, array):
        if name not in array:
            raise UIn_ResourceError(type_name, name)
        return array[name]

    # timeout in ms
    def table_set_entry_timeout(self, client, table_name, entry_handle, timeout):

        table = self.get_res("table", table_name, TABLES)
        if not table.support_timeout:
            raise UIn_Error(
                "Table {} does not support entry timeouts"  
            )
        print "Setting a", timeout, "ms timeout for entry", entry_handle
        client.bm_mt_set_entry_ttl(0, table_name, entry_handle, timeout)

    def table_modify_entry(self, client, table_name, action_name, entry_handle, action_params):

        table = self.get_res("table", table_name, TABLES)
        if action_name not in table.actions:
            raise UIn_Error(
                "Table %s has no action %s" % (table_name, action_name)
            )
        action = ACTIONS[action_name]
        runtime_data = parse_runtime_data(action, action_params)
        
        print "Modifying entry", entry_handle, "for", MatchType.to_str(table.match_type), "match table", table_name
        entry_handle = client.bm_mt_modify_entry(
            0, table_name, entry_handle, action_name, runtime_data
        )
        return entry_handle

    def table_add_entry(self, client,table_name, action_name, match_key, action_params, prio=0):
        "Add entry to a match table: table_add <table name> <action name> <match fields> => <action parameters> [priority]"
        table = self.get_res("table", table_name, TABLES)
        if action_name not in table.actions:
            raise UIn_Error(
                "Table %s has no action %s" % (table_name, action_name)
            )
        
        if table.match_type in {MatchType.TERNARY, MatchType.RANGE}:
            try:
                priority = prio
            except:
                raise UIn_Error(
                    "Table is ternary, but could not extract a valid priority from args"
                )
        else:
            priority = 0
        
        # guaranteed to exist
        action = ACTIONS[action_name]
       
        if len(match_key) != table.num_key_fields():
            raise UIn_Error(
                "Table %s needs %d key fields" % (table_name, table.num_key_fields())
            )
        
        runtime_data = parse_runtime_data(action, action_params)
        
        match_key = parse_match_key(table, match_key)
        
        print "Adding entry to", MatchType.to_str(table.match_type), "match table", table_name
        
        entry_handle = client.bm_mt_add_entry(
            0, table_name, match_key, action_name, runtime_data,
            BmAddEntryOptions(priority = priority)
        )
        
        print "Entry has been added with handle", entry_handle
        return entry_handle

    def table_delete_entry(self, client, table_name, entry_handle):
        "Delete entry from a match table: table_delete <table name><entry handle>"
        table = self.get_res("table", table_name, TABLES)
        print "Deleting entry", entry_handle, "from", table_name
        client.bm_mt_delete_entry(0, table_name, entry_handle)  

    def table_default_entry(self, client,table_name, action_name, action_params):
        table = self.get_res("table", table_name, TABLES)
        if action_name not in table.actions:
            raise UIn_Error(
                "Table %s has no action %s" % (table_name, action_name)
            )
        action = ACTIONS[action_name]
        if len(action_params) != action.num_params():
            raise UIn_Error(
                "Action %s needs %d parameters" % (action_name, action.num_params())
            )
        runtime_data = parse_runtime_data(action, action_params)
        client.bm_mt_set_default_action(0, table_name, action_name, runtime_data)

    # FIXME Parametrize
    def add_flow_id_entry(self, client, srcip, sport, proto, dstip, dport):
        self.table_add_entry(client, FLOW_ID, NO_OP,[srcip, sport, proto, dstip, dport],[])

    def block_flow_id_entry(self, client, srcip, sport, proto, dstip, dport):
        self.table_add_entry(client, FLOW_ID, DROP,[srcip, sport, proto, dstip, dport],[])

    def add_modbus_entry(self, client, srcip, sport, funcode, payload_length):
        self.table_add_entry(client, MODBUS, NO_OP, [srcip, sport, funcode, payload_length],[])

    def add_block_entry(self, client, srcip, proto, dstip, dport):
        self.table_add_entry(client, BLOCK_HOSTS, DROP, [srcip, proto, dstip, dport],[])
    
    def block_modbus_entry(self, client, srcip, sport, funcode, payload_length):
        self.table_add_entry(client, MODBUS, DROP, [srcip, sport, funcode, payload_length])

    def add_send_frame_entry(self, client, port, mac):
        self.table_add_entry(client, SEND_FRAME, NO_OP, [port],[])
    
    def add_ipv4_entry(self, client, ip_addr, port):
        self.table_add_entry(client, IPV4_LPM, SET_EGRESS, [str(ip_addr)], [port])

    def add_forward_entry(self, client, ip_addr, mac):
        self.table_add_entry(client, FORWARD, DMAC, [str(ip_addr)],[mac]) 
    
    def add_arp_resp_entry(self, client, ip_addr, mac):
        # opcode request
        self.table_add_entry(client, ARP_RESP, RESP, [ip_addr, str(1)],[mac])
    
    def add_arp_forw_entry(self, client, in_port, out_port):
        self.table_add_entry(client, ARP_FORW, REDIRECT, [in_port], [out_port])

    def get_resp_switch(self, srcip, dstip):
        #List of switch where the flow is passing
        resp_switch = [] 
        for switch in self.switches: 
            sw = self.switches[switch]
            if sw.is_responsible(srcip) or sw.is_responsible(dstip):
                resp_switch.append(sw)
        return resp_switch

    # resp_sw is a list of switch object, f is a function (allow or drop flow)
    def deploy_flow_id_rules(self, resp_sw, srcip, sport, proto, dstip, dport, f, flag, wl_orig=False):
        rule = (srcip,sport,proto, dstip, dport)
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            # Rule was not installed on this switch
            if ((self.flow_table.is_rule_installed(rule) and sw.sw_id not in self.flow_table.rule_to_switches(rule))
                or not self.flow_table.is_rule_installed(rule)): 
                f(client, srcip, sport, proto, dstip, dport)
                self.flow_table.add_rule(rule,sw.sw_id, sw.p4_table[FLOW_ID],flag, wl_orig)
                sw.p4_table[FLOW_ID] += 1
                if int(proto) == IP_PROTO_TCP:
                    f(client, dstip, dport, proto, srcip, sport) 
                    self.flow_table.add_rule((dstip, dport, proto, srcip, sport), sw.sw_id, sw.p4_table[FLOW_ID],flag, wl_orig)
                    sw.p4_table[FLOW_ID] += 1
            else:
                # if another rule was installed on this switch with a different action we need to remove it
                if self.flow_table.get_type_entry(rule, sw.sw_id) != flag:
                    entry_handle = self.flow_table.get_num_entry(rule, sw.sw_id)
                    self.table_delete_entry(client, FLOW_ID, entry_handle)
                    self.flow_table.delete_rule(rule, sw.sw_id)
                    f(client, srcip, sport, proto, dstip, dport)
                    self.flow_table.add_rule(rule, sw.sw_id, sw.p4_table[FLOW_ID],flag, wl_orig)
                    sw.p4_table[FLOW_ID] += 1
                    if int(proto) == IP_PROTO_TCP:
                        f(client, dstip, dport, proto, srcip, sport) 
                        self.flow_table.add_rule((dstip, dport, proto, srcip, sport), sw.sw_id, sw.p4_table[FLOW_ID],flag, wl_orig)
                        sw.p4_table[FLOW_ID] += 1

    # resp_sw is a list of switch_id present in the path between two endpoints
    def deploy_block_host_rules(self, resp_sw, srcip, proto, dstip, dport, f, flag, wl_orig=False):
        rule = (srcip, proto, dstip, dport)
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            if ((self.block_hosts_table.is_rule_installed(rule) and sw.sw_id not in self.block_hosts_table.rule_to_switches(rule))
                or not self.block_hosts_table.is_rule_installed(rule)):
                f(client, srcip, proto, dstip, dport)
                self.block_hosts_table.add_rule(rule, sw.sw_id, sw.p4_table[BLOCK_HOSTS], flag, wl_orig)
                sw.p4_table[BLOCK_HOSTS] += 1 
            
    # resp_sw is a list of switch_id 
    def deploy_delete_flow_rules(self, resp_sw, srcip, sport, proto, dstip, dport):
        flow = (srcip, sport, proto, dstip, dport)
        if self.flow_table.is_rule_installed(flow): 
            for sw_id in resp_sw:
                client = self.clients[sw_id]
                if sw_id in self.flow_table.rule_to_switches(flow):
                    entry_handle = self.flow_table.get_num_entry(flow, sw_id)
                    self.table_delete_entry(client, FLOW_ID, entry_handle)
                    self.flow_table.delete_rule(flow, sw_id)

        
    # resp_sw is a list of switch_id present in the path between the two modbus endpoints
    def deploy_modbus_rules(self, resp_sw, srcip, sport, funcode, payload_length, f, flag, wl_orig=False):
        rule = (srcip,sport, funcode, payload_length)
        for sw_id in resp_sw:
            switch = self.switches[sw_id]
            client = self.clients[sw_id]
            if ((self.modbus_table.is_rule_installed(rule) and sw_id not in self.modbus_table.rule_to_switches(rule))
                or not self.modbus_table.is_rule_installed(rule)):
                f(client, srcip, sport, funcode, payload_length)
                self.modbus_table.add_rule(rule, sw_id, switch.p4_table[MODBUS],flag, wl_orig)
                switch.p4_table[MODBUS] += 1
            else:
                if self.modbus_table.get_type_entry(rule, sw_id) != flag:
                    entry_handle = self.modbus_table.get_num_entry(rule,sw_id)
                    self.table_delete_entry(client, MODBUS, entry_handle)
                    self.flow_table.delete_rule(rule, sw.sw_id)
                    f(client, srcip, sport, funcode, payload_length)
                    self.modbus_table.add_rule(rule, sw_id,sw.p4_table[MODBUS], flag, wl_orig)
                    sw.p4_table[MODBUS] += 1

    def is_flow_installed(self, flow):
        (srcip, sport, proto, dstip, dport) = flow
        if int(proto) == IP_PROTO_TCP:
            return (self.flow_table.is_rule_installed(flow) or \
                    self.flow_table.is_rule_installed((dstip, dport, proto, srcip, sport)))
        else:
            return self.flow_table.is_rule_installed(flow) 

    def dessiminate_rules(self, filename):
        PSH = 0x08
        ACK = 0x10
        SYN = 0x02
        FIN = 0x01
        RST = 0x04
        terminated_conn = {}
        capture = rdpcap(filename)    
        for pkt in capture:
            if IP in pkt:
                srcip = pkt[IP].src
                dstip = pkt[IP].dst
                if pkt[IP].proto == IP_PROTO_TCP:
                    proto = str(pkt[IP].proto)
                    sport = str(pkt[TCP].sport)
                    dport = str(pkt[TCP].dport)
                    flags = pkt[TCP].flags
                    flow = (srcip, sport, proto, dstip, dport)

                    if not self.is_flow_installed(flow) and terminated_conn.get(flow,-1) < 2:
                        resp_switch = self.get_resp_switch(srcip, dstip)  
                        self.deploy_flow_id_rules(resp_switch, srcip, sport, proto, dstip, dport, self.add_flow_id_entry, RULE_ALLOW, RULE_ORIGINAL)

                    if (flags & PSH) and (flags & ACK) and (sport == "5020" or dport == "5020"):
                        funcode = str(pkt[Modbus].funcode)
                        payload_length = str(pkt[Modbus].length)
                        if not self.modbus_table.is_rule_installed((srcip, sport, funcode, payload_length)):
                            resp_switch = self.flow_table.rule_to_switches(flow)
                            self.deploy_modbus_rules(resp_switch, srcip, sport, funcode, payload_length, self.add_modbus_entry, RULE_ALLOW, RULE_ORIGINAL)

                    if (flags & RST):
                        self.update_table(FLOW_ID)
                        resp_switch = self.flow_table.rule_to_switches(flow)
                        self.deploy_delete_flow_rules(resp_switch, srcip, sport, proto, dstip, dport)
                        self.deploy_delete_flow_rules(resp_switch, dstip, dport, proto, srcip, sport)
                    
                    if (flags & FIN):
                        #Register if server has send an FIN packet
                        terminated_conn[flow] = terminated_conn.get(flow,0) + 1
     
                    if (flags & ACK):
                        self.update_table(FLOW_ID)
                        # Destination has received a FIN and send an ACK
                        d_flow = (dstip, dport, proto, srcip, sport)
                        if d_flow in terminated_conn:
                            terminated_conn[d_flow] += 1 
                            
                        if terminated_conn.get(flow,-1) > 1 and terminated_conn.get(d_flow,-1) > 1: 
                            resp_switch = self.flow_table.rule_to_switches(flow)
                            self.deploy_delete_flow_rules(resp_switch, srcip, sport, proto, dstip, dport)
                            self.deploy_delete_flow_rules(resp_switch, dstip, dport, proto, srcip, sport)

                #TODO UDP traffic
    def clear_table(self,table_name):
        table = self.get_res("table", table_name, TABLES)
        for client_id, client in self.clients.iteritems():
            client.bm_mt_clear_entries(0, table_name, False) 
        # TODO clear self.flow_table
    def hexstr(self, v):
        return "".join("{:02x}".format(ord(c)) for c in v)

    def parse_hexstr(self,s):
        def ip_string(s):
            ip = []
            for i in xrange(0, len(s), 2):
                block = int(s[i:i+2],16)
                a = str(block) 
                ip.append(a)
            return ".".join(ip)

                 
        l = s.split(',')
        assert len(l) == 5
        srcip = ip_string(l[0]) 
        sport = str(int(l[1],16))
        proto = str(int(l[2],16))
        dstip = ip_string(l[3])
        dport = str(int(l[4],16))
        return (srcip, sport, proto, dstip, dport) 

    # FIXME For now only for flow table
    def update_table(self, table_name):
        for client_id, client in self.clients.iteritems():
            entries = client.bm_mt_get_entries(0,table_name)
            table = self.get_res("table", table_name, TABLES) 
            for e in entries:
                s = ""
                for param in e.match_key:
                   s += self.hexstr(param.exact.key) + ","
                flow = self.parse_hexstr(s[:-1])
                action = e.action_entry.action_name
                if action == NO_OP:
                    rule_type = RULE_ALLOW 
                else:
                    rule_type = RULE_DROP
                self.flow_table.update_rule(flow, client_id, e.entry_handle, rule_type )
                #print ("%s, %s, %s, %s") % (client_id, e.entry_handle, flow, e.action_entry.action_name)
        


    def setup_default_entry(self, ids_sw_id):
        for switch in self.switches:
            sw = self.switches[switch]
            client = self.clients[sw.sw_id]
            #self.ids_sw_id = ids_sw_id
            is_ids_sw_id = sw.is_responsible(sw.ids_addr)
            self.table_default_entry(client, SEND_FRAME, DROP, [])
            self.table_default_entry(client, FORWARD, NO_OP, [])
            self.table_default_entry(client, TCP_FLAGS, NO_OP, [])
            self.table_default_entry(client, PKT_CLONED, NO_OP, [])

            # Set rule in  PKT_CLONED to distinguish instance_type of packet
            #self.table_default_entry(client, TCP_FLAGS, CLONE_I2E, [])
            #self.table_add_entry(client, PKT_CLONED, ADD_TAG, [CLONE_PKT_FLAG],[sw.sw_id, sw.ids_addr, sw.ids_port]) 
            if is_ids_sw_id:
                self.ids_sw_id = sw.sw_id 
                self.table_default_entry(client, FLOW_ID, NO_OP, [])
                self.table_default_entry(client, MODBUS, NO_OP, [])
                #self.table_add_entry(client, SRTAG, REMOVE_TAG, [IP_PROTO_SRTAG], [sw.ids_port])
                self.table_add_entry(client, SRTAG, REMOVE_TAG, [IP_PROTO_SRTAG], ["1"])
                self.table_default_entry(client, IDSTAG, NO_OP, [])
                self.table_default_entry(client, IDSTAG_ADD_TAB, NO_OP, [])
                self.table_add_entry(client, IDSTAG_ADD_TAB, ADD_IDSTAG, ["1"], ["9"])
                self.ids_tag[sw.sw_id] = 0
            else:
                self.table_default_entry(client, FLOW_ID, ADD_TAG, [ sw.sw_id, sw.ids_addr, sw.ids_port])
                self.table_default_entry(client, MODBUS, ADD_TAG, [sw.sw_id, sw.ids_addr, sw.ids_port])
                self.table_default_entry(client, IDSTAG_ADD_TAB, NO_OP,[])
                self.table_default_entry(client, IDSTAG, NO_OP, [])
                self.table_add_entry(client, IDSTAG, REMOVE_IDSTAG , [IP_PROTO_IDSTAG, "9", sw.ids_port], [])
                self.ids_tag[sw.sw_id] = 0

            self.table_default_entry(client, ARP_FORW_REQ, STORE_ARP, [sw.gw_port])
            self.table_default_entry(client, IPV4_LPM, SET_EGRESS, [sw.gw_port])
            self.table_default_entry(client, SRTAG, NO_OP, [])
            self.table_default_entry(client, ARP_RESP, NO_OP, [])
            self.table_default_entry(client, ARP_FORW_RESP, FORWARD_ARP, [])
            self.table_default_entry(client, BLOCK_HOSTS, NO_OP, [])


            for interface in sw.interfaces:
                for iname in interface:
                    port = iname
                    mac = interface[iname]     
                    self.add_send_frame_entry(client, port, mac) 

            for arp_entry in sw.arp_table:
                for ip_addr in arp_entry:
                    mac = arp_entry[ip_addr]
                    self.add_forward_entry(client, ip_addr, mac) 

            for route in sw.routing_table:
                for dest in route:
                    port = route[dest]
                    self.add_ipv4_entry(client, IPNetwork(dest), port)

            ip_addr = sw.real_ip
            mac = sw.interfaces[0]["1"]
            self.add_arp_resp_entry(client, ip_addr, mac)
            for entry in sw.arp_table:
                for ip, mac in entry.iteritems():
                    self.add_arp_resp_entry(client, ip, mac)
                 


def load_json_config(standard_client=None, json_path=None):
    load_json_str(utils.get_json_config(standard_client, json_path))


def main(sw_config, capture, ip, port, ids_sw_id):
    print "Creating switches"
    switches = create_switches(sw_config) 
    controller = Controller()
    print "Connecting to switches and setting default entry"
    controller.setup_connection(switches) 
    controller.setup_default_entry(ids_sw_id)
    print "Installing rules according to the capture"
    if capture:
        controller.dessiminate_rules(capture)
    processor = Processor(controller)
    transport = TSocket.TServerSocket(port=port)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    server.serve()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--conf', action='store', dest='conf', help='file containing description of switch')
    parser.add_argument('--capture', action='store', dest='capture',default=None, help='training set capture for the whitelist')
    parser.add_argument('--ip', action='store', dest ='ip', default='172.0.10.2', help='ip address of the controller')
    parser.add_argument('--port', action='store', dest='port', type=int, default=2050, help='port used by controller')
    parser.add_argument('--ids', action='store', dest='ids_sw_id',default='3', help='datapath id of the switch connected to the IDS')
    args = parser.parse_args()
    main(args.conf, args.capture, args.ip, args.port, args.ids_sw_id)
