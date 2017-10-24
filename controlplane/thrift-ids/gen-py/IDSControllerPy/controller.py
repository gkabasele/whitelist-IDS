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

        Add rule to the table
    '''
    @verify
    def add_rule(self, rule, switch_id, num_entry):
        if rule not in self.rules:
            self.rules[rule] = {switch_id : num_entry}
        elif switch_id not in self.rules[rule]:
            self.rules[rule][switch_id] = num_entry

    '''
        rule : fields used for matching
        
        return the list of switchs containing a rule for this fields
    '''
    @verify
    def rule_to_switches(self, rule):
        return self.rules[rule].keys()

    '''
        rule : fields used for matching
    '''
    @verify
    def get_num_entry(self, rule, switch_id):
        return self.rules[rule][switch_id]
    
    @verify
    def is_rule_installed(self, rule):
        return rule in self.rules
        
bind_layers(TCP, Modbus, dport=5020)
bind_layers(TCP, Modbus, sport=5020)

IP_PROTO_TCP = 6
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

# Action name
DROP = '_drop'
NO_OP = '_no_op'
ADD_TAG = 'add_miss_tag'
REWRITE = 'rewrite_mac'
DMAC = 'set_dmac'
SET_EGRESS = 'set_egress_port'
ADD_PORT = 'add_expected_port'
RESP = 'respond_arp'
STORE_ARP = 'store_arp_in'
FORWARD_ARP = 'forward_arp'


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
        self.p4_table = {FLOW_ID : 0 , MODBUS: 0}

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
        # Flow : srcip, sport, proto, dstip, dport
        self.flow_table = RuleTables(5)
        # Modbus : srcip, sport, funcode, payload_length, length
        self.modbus_table = RuleTables(5)
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

    # Forward packet but send clone to ids
    def mirror(self, req, sw):
        pass

    # Forward packet to ids
    def redirect(self, req, sw):
        pass

    # Block flow
    def block(self, req, sw):
        pass
    
    # Delete flow from the whitelist    
    def delete(self, req, sw):
        pass

    # install flow in the whitelist
    def allow(self, req, sw):
        if req != None:
            print "%s" % req 
            #Convert to string
            proto = str(req.proto)
            sport = str(req.srcport)
            dport = str(req.dstport)
           
            if not self.is_flow_installed( (req.srcip, sport, proto, req.dstip, dport)): 
                resp_sw = self.get_resp_switch(req.srcip, req.dstip)
                self.deploy_flow_id_rules(resp_sw, req.srcip, sport, proto, req.dstip, dport)
        else:
            err = IDSControllerException(1, "cannot read request")
            raise err 


    # deprecated
    def waiting_request(self, ip, port):
        server = (ip,port)
        print "Starting controller"
        self.sock.bind(server)
        self.sock.listen(1) 
        while True:
            newsock, ids = self.sock.accept()
            conn = ssl.wrap_socket(newsock,
                                   server_side=True,
                                   certfile=Communication.PEM_PATH,
                                   ssl_version=ssl.PROTOCOL_TLSv1)
            try:
                print "connected to ids"
                while True:
                    data = Communication.recv_msg(conn)
                    print "Received req"
                    if data:
                        flow = pickle.loads(data)
                        code = ERROR
                        #FIXME use dict.get
                        if flow.install:
                            if (flow.srcip, flow.dstip, flow.proto) in self.history:
                                resp_sw = self.history[(flow.srcip, flow.dstip, flow.proto)]

                                print "Reason: ",flow.reason

                                if flow.reason == PORT_MISS: 
                                    print "Port miss: %s-%s " % (flow.sport, flow.dport) 
                                    if (flow.srcip, flow.dstip, flow.proto, flow.sport, flow.dport) not in self.history:
                                        self.deploy_ex_port_rules(resp_sw, flow.srcip, flow.dstip, flow.sport, flow.dport) 
                                        self.history[(flow.srcip, flow.dstip, flow.proto, flow.sport, flow.dport)] = resp_sw
                                        self.history[(flow.dstip, flow.srcip, flow.proto, flow.dport, flow.sport)] = resp_sw
                                        code = OK

                                elif flow.reason == FUN_MISS:
                                    print "Funcode miss: ", flow.funcode
                                    if (flow.srcip, flow.sport, flow.funcode) not in self.history and (int(flow.funcode) > 0):
                                        self.history[(flow.srcip, flow.sport, flow.funcode)] = True 
                                        self.history[(flow.srcip, flow.sport, flow.funcode, flow.length)] = True
                                        self.deploy_modbus_rules(resp_sw, flow.srcip, flow.sport, flow.funcode)
                                        self.deploy_modbus_payload_rules(resp_sw, flow.srcip, flow.sport, flow.funcode, flow.length)
                                        if (flow.dstip, flow.dport, flow.funcode) not in self.history:
                                            self.history[(flow.dstip, flow.dport, flow.funcode)] = True 
                                            self.deploy_modbus_rules(resp_sw, flow.dstip, flow.dport, flow.funcode)
                                        code =  OK

                                elif flow.reason == PAYLOAD_SIZE_MISS:
                                    print "Payload size miss: ", flow.length
                                    # It is likely that it is a response from the modbus server
                                    if ((flow.dstip, flow.dport, flow.funcode) in self.history and
                                       (flow.srcip, flow.sport, flow.funcode) in self.history and
                                        flow.sport == "5020"): 
                                        self.history[(flow.srcip, flow.sport, flow.funcode, flow.length)] = True
                                        self.deploy_modbus_payload_rules(resp_sw, flow.srcip, flow.sport, flow.funcode, flow.length)
                                        code = OK
                                        
                                else:
                                    print "unknown reason"
                                    code = ERROR
                            else:
                                print "Adding new flow"
                                resp_sw = self.get_resp_switch(flow.srcip, flow.dstip)
                                self.deploy_flow_id_rules(resp_sw, flow.srcip, flow.dstip, flow.proto)
                                self.deploy_ex_port_rules(resp_sw, flow.srcip, flow.dstip, flow.sport, flow.dport)
                                self.add_history_entry(flow.srcip, flow.dstip, flow.proto, flow.sport, flow.dport, resp_sw)
                                code = OK
                        else:
                           print "Dropping request"
                           client = self.clients[flow.identifier] 
                           if (flow.srcip, flow.sport, flow.funcode) not in self.history and (int(flow.funcode) > 0):
                                self.table_add_entry(client, MODBUS, DROP, [flow.srcip, flow.sport, flow.funcode],[])
                                self.table_add_entry(client, MODBUS_PAYLOAD, DROP, [flow.srcip, flow.sport, flow.funcode, flow.length],[])
                                self.history[(flow.srcip, flow.sport, flow.funcode)] = True 
                                self.history[(flow.srcip, flow.sport, flow.funcode, flow.length)] = True

                           code = OK

                        # Notifying ids about the rule installation
                        resp = FlowResponse(flow.req_id, code) 
                        Communication.send(resp,conn)
                    else:
                        resp = FlowResponse(flow.req_id, code)
                        Communication.send(resp, conn)
            finally:
                conn.shutdown(sock.SHUT_RDWR)
                conn.close()
    
    def get_res(self, type_name, name, array):
        if name not in array:
            raise UIn_ResourceError(type_name, name)
        return array[name]

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

    def add_flow_id_entry(self, client, srcip, sport, proto, dstip, dport):
        self.table_add_entry(client, FLOW_ID, NO_OP,[srcip, sport, proto, dstip, dport],[])

    def add_modbus_entry(self, client, srcip, sport, funcode, payload_length, length):
        self.table_add_entry(client, MODBUS, NO_OP, [srcip, sport, funcode, payload_length, length],[])

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

    # resp_sw is a list of switch object
    def deploy_flow_id_rules(self, resp_sw, srcip, sport, proto, dstip, dport):
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            self.add_flow_id_entry(client, srcip, sport, proto, dstip, dport)
            self.flow_table.add_rule((srcip, sport, proto, dstip, dport), sw.sw_id, sw.p4_table[FLOW_ID])
            sw.p4_table[FLOW_ID] += 1
            if int(proto) == IP_PROTO_TCP:
                self.add_flow_id_entry(client, dstip, dport, proto, srcip, sport) 
                self.flow_table.add_rule((dstip, dport, proto, srcip, sport), sw.sw_id, sw.p4_table[FLOW_ID])

    # resp_sw is a list of switch_id present in the corresponding table
    def deploy_modbus_rules(self, resp_sw, srcip, sport, funcode, payload_length, length):
        for sw_id in resp_sw:
            switch = self.switches[sw_id]
            client = self.clients[sw_id]
            self.add_modbus_entry(client, srcip, sport, funcode, payload_length, length)
            self.modbus_table.add_rule((srcip, sport, funcode, payload_length, length), switch.sw_id, switch.p4_table[MODBUS])
            switch.p4_table[MODBUS] += 1

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
        capture = rdpcap(filename)    
        for pkt in capture:
            srcip = pkt[IP].src
            dstip = pkt[IP].dst
            if pkt[IP].proto == IP_PROTO_TCP:
                proto = str(pkt[IP].proto)
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)
                if not self.is_flow_installed((srcip, sport, proto, dstip, dport)):
                    resp_switch = self.get_resp_switch(srcip, dstip)  
                    self.deploy_flow_id_rules(resp_switch, srcip, sport, proto, dstip, dport)

                flags = pkt[TCP].flags
                if (flags & PSH) and (flags & ACK) and (sport == "5020" or dport == "5020"):
                    funcode = str(pkt[Modbus].funcode)
                    payload_length = str(pkt[Modbus].length)
                    length = str(len(pkt))
                    if not self.modbus_table.is_rule_installed((srcip, sport, funcode, payload_length, length)):
                        resp_switch = self.flow_table.rule_to_switches((srcip, sport, proto, dstip, dport))
                        self.deploy_modbus_rules(resp_switch, srcip, sport, funcode, payload_length, length)
            #TODO UDP traffic

    def setup_default_entry(self):
        for switch in self.switches:
            sw = self.switches[switch]
            client = self.clients[sw.sw_id]
            is_ids_sw = sw.is_responsible(sw.ids_addr)

            self.table_default_entry(client, SEND_FRAME, DROP, [])
            self.table_default_entry(client, FORWARD, NO_OP, [])
            if is_ids_sw:
                self.table_default_entry(client, FLOW_ID, NO_OP, [])
                self.table_default_entry(client, MODBUS, NO_OP, [])
            else:
                self.table_default_entry(client, FLOW_ID, ADD_TAG, [ sw.sw_id, sw.ids_addr, sw.ids_port])
                self.table_default_entry(client, MODBUS, ADD_TAG, [sw.sw_id, sw.ids_addr, sw.ids_port])

            self.table_default_entry(client, ARP_FORW_REQ, STORE_ARP, [sw.gw_port])
            self.table_default_entry(client, IPV4_LPM, SET_EGRESS, [sw.gw_port])

            self.table_default_entry(client, ARP_RESP, NO_OP, [])
            self.table_default_entry(client, ARP_FORW_RESP, FORWARD_ARP, [])


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


def main(sw_config, capture, ip, port):
    print "Creating switches"
    switches = create_switches(sw_config) 
    controller = Controller()
    print "Connecting to switches and setting default entry"
    controller.setup_connection(switches) 
    controller.setup_default_entry()
    print "Installing rules according to the capture"
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
    parser.add_argument('--capture', action='store', dest='capture', help='training set capture for the whitelist')
    parser.add_argument('--ip', action='store', dest ='ip', default='172.0.10.2', help='ip address of the controller')
    parser.add_argument('--port', action='store', dest='port', type=int, default=2050, help='port used by controller')
    args = parser.parse_args()
    main(args.conf, args.capture, args.ip, args.port)
