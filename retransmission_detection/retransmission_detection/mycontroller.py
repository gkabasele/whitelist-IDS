#!/usr/bin/env python2
import argparse
import grpc
import os
import threading
import socket
import pickle
import logging
import sys
from time import sleep
import pdb

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_HOST_PORT_MUL = 2
S1_S2_PORT = 2
S1_S3_PORT = 3

S2_S1_PORT = 3
S2_S3_PORT = 4

S3_S1_PORT = 2
S3_S2_PORT = 3

SRTAG_TYPE = 0x1212
SRTAGIDS_TYPE = 0x1213

class Flow(object):

    def __init__(self, saddr, sport, daddr, dport, proto, flow_id=None):
        self.saddr = saddr
        self.sport = sport
        self.daddr = daddr
        self.dport = dport
        self.proto = proto
        self.flow_id = flow_id
        self.nb_retrans = 0
        self.retrans = False
        self.is_terminated = False
    
    def get_rev(self):
        return Flow(self.daddr, self.dport, self.saddr, self.sport,
                    self.proto)

    def __hash__(self):
        return hash((self.saddr, self.sport, self.daddr, self.dport, self.proto))

    def __eq__(self, other):
        return (self.saddr == other.saddr, self.sport == other.sport,
                self.daddr == other.daddr, self.dport == other.dport,
                self.proto == other.proto)

    def __str__(self):
        return "{}:{}<->{}:{} ({})".format(self.saddr, self.sport,
                                           self.daddr, self.dport, self.proto)
    def __repr__(self):
        return self.__str__()

    def crash_flow(self):
        return (self.nb_retrans >= 3
                or self.is_terminated
                or self.retrans)

    def compare_flow(self, other):
        return other.saddr == self.saddr and other.dport == self.dport

class Controller(object):

    def __init__(self, ip, port, backup, p4info_file_path, bmv2_file_path):

        self.flows = dict()
        self.flows_id = dict()
        self.ip = ip
        self.port = port
        self.flow_id = 1
        self.lock = threading.Lock()

        self.topo = None
        self.links = None
        self.map_flow_retrans = None
        self.map_switches_flows = None

        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.bmv2_file_path = bmv2_file_path

        self.backup = backup

    def create_flow(self, saddr, sport, daddr, dport, proto):
        f = Flow(saddr, sport, daddr, dport, proto, self.flow_id)
        if self.flow_id not in self.flows:
            self.flows[self.flow_id] = f
            self.flows_id[f] = self.flow_id
        else:
            logging.error("Flow {} with id {} already exist".format(f, f.flow_id))
            raise ValueError("Flow {}  with id {} already exist".format(f, f.flow_id))
        self.flow_id += 1
        return f

    def get_switch_path_from_flow(self, start, end, path):
        path = path + [start]
        if start == end:
            return path
        if not self.links.has_key(start):
            return None
        for node in self.links[start]:
            if node not in path:
                newpath = self.get_switch_path_from_flow( node, end, path)
                if newpath:
                    return newpath
        return None

    def deleteBackUpInitFirstRules(self, sw, saddr, daddr, dport):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.backup_init_flow_exact",
        match_fields={
            "hdr.ipv4.srcAddr": saddr,
            "hdr.ipv4.dstAddr": daddr,
            "hdr.tcp.dstPort": dport
        },
        action_name="MyIngress.clone_for_ids",
        action_params={})
        sw.DeleteTableEntry(table_entry)
        print("Delete backup init first rule on %s" % sw.name)
        logging.debug("Delete backup init first rule on %s" % sw.name)


    def writeBackUpInitFirstRules(self, sw, saddr, daddr, dport):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.backup_init_flow_exact",
        match_fields={
            "hdr.ipv4.srcAddr": saddr,
            "hdr.ipv4.dstAddr": daddr,
            "hdr.tcp.dstPort": dport
        },
        action_name="MyIngress.clone_for_ids",
        action_params={})
        sw.WriteTableEntry(table_entry)
        print("Install backup init first rule on %s" % sw.name)
        logging.debug("Install backup init first rule on %s" % sw.name)

    def deleteBackUpInitRules(self, sw, saddr, daddr, dport):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.backup_init_flow_exact",
        match_fields={
            "hdr.ipv4.srcAddr": saddr,
            "hdr.ipv4.dstAddr": daddr,
            "hdr.tcp.dstPort": dport
        },
        action_name="MyIngress.do_nothing",
        action_params={})
        sw.DeleteTableEntry(table_entry)
        print("Delete backup init rule on %s" % sw.name)
        logging.debug("Delete backup init rule on %s" % sw.name)

    def writeBackUpInitRules(self, sw, saddr, daddr, dport):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.backup_init_flow_exact",
        match_fields={
            "hdr.ipv4.srcAddr": saddr,
            "hdr.ipv4.dstAddr": daddr,
            "hdr.tcp.dstPort": dport
        },
        action_name="MyIngress.do_nothing",
        action_params={})
        sw.WriteTableEntry(table_entry)
        print("Install backup init rule on %s" % sw.name)
        logging.debug("Install backup init rule on %s" % sw.name)

    def deleteBackUpRules(self, sw, saddr, daddr, dport):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.backup_flow_exact",
        match_fields={
            "hdr.ipv4.dstAddr": daddr,
            "hdr.ipv4.srcAddr": saddr,
            "hdr.tcp.srcPort": dport
        },
        action_name="MyIngress.do_nothing",
        action_params={})
        sw.DeleteTableEntry(table_entry)
        print("Delete backup rule on %s" % sw.name)
        logging.debug("Delete init rule on %s" % sw.name)

    def writeBackUpRules(self, sw, saddr, daddr, dport):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.backup_flow_exact",
        match_fields={
            "hdr.ipv4.dstAddr": daddr,
            "hdr.ipv4.srcAddr": saddr,
            "hdr.tcp.srcPort": dport
        },
        action_name="MyIngress.do_nothing",
        action_params={})
        sw.WriteTableEntry(table_entry)
        print("Install backup rule on %s" % sw.name)
        logging.debug("Install init rule on %s" % sw.name)

    def writeCloneRules(self, sw, ip_addr): 
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.clone_exact",
        match_fields={
            "hdr.ipv4.srcAddr": ip_addr
        },
        action_name="MyIngress.change_to_srtag",
        action_params={})
        sw.WriteTableEntry(table_entry)
        print("Install clone rule on %s" % sw.name)
        logging.debug("Install clone rule on %s" % sw.name)

    def writeRedirectRules(self, sw, ether_type, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.srtag_exact",
        match_fields={
            "hdr.ethernet.etherType": ether_type
        },
        action_name="MyIngress.srtag_forward",
        action_params={
            "port": out_port 
        })
        sw.WriteTableEntry(table_entry)
        print("Install redirection rule on %s" % sw.name)
        logging.debug("Install redirection rule on %s" % sw.name)
        
    def writeLastRedirectRules(self, sw, ether_type, eth_dst, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.srtag_exact",
        match_fields={
            "hdr.ethernet.etherType": ether_type
        },
        action_name="MyIngress.change_to_ip_and_forward",
        action_params={
            "dstAddr": eth_dst,
            "port": out_port 
        })
        sw.WriteTableEntry(table_entry)
        print("Install redirection rule on %s" % sw.name)
        logging.debug("Install redirection rule on %s" % sw.name)

    def writeIDSVerificationRules(self, sw, dst_addr, in_port, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.ids_verification",
        match_fields={
            "standard_metadata.ingress_port": in_port,
            "hdr.ipv4.dstAddr": dst_addr
        },
        action_name="MyIngress.change_to_srtag_ids",
        action_params={
            "port": out_port
        })
        sw.WriteTableEntry(table_entry)
        print("Install ids verification rule on %s" % sw.name)
        logging.debug("Install ids verification rule on %s" % sw.name)

    def writeIDSClearRules(self, sw, ether_type, dst_ip, eth_dst, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.ids_clear",
        match_fields={
            "hdr.ethernet.etherType": ether_type,
            "hdr.ipv4.dstAddr": dst_ip
        },
        action_name="MyIngress.change_to_ip_and_forward",
        action_params={
            "dstAddr": eth_dst,
            "port": out_port 
        })
        sw.WriteTableEntry(table_entry)
        print("Install ids clear rule on %s" % sw.name)
        logging.debug("Install ids clear rule on %s" % sw.name)

    def writeMetaRules(self, ingress_sw, flow):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.metaRetrans_exact",
        match_fields={
            "meta.isRetrans": 1,
            "hdr.ipv4.srcAddr": flow.saddr,
            "hdr.tcp.srcPort":  flow.sport,
            "hdr.ipv4.dstAddr": flow.daddr,
            "hdr.tcp.dstPort":  flow.dport,
            "hdr.ipv4.protocol": flow.proto
        },
        action_name="MyIngress.update_retrans_counter",
        action_params={
            "flow_id": flow.flow_id
        })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ingress meta rule on %s" % ingress_sw.name)
        logging.debug("Installed ingress meta rule on %s" % ingress_sw.name)
    
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.metaTermination_exact",
        match_fields={
            "meta.isTerminated": 1,
            "hdr.ipv4.srcAddr": flow.saddr,
            "hdr.tcp.srcPort":  flow.sport,
            "hdr.ipv4.dstAddr": flow.daddr,
            "hdr.tcp.dstPort":  flow.dport,
            "hdr.ipv4.protocol": flow.proto
        },
        action_name="MyIngress.update_terminated_counter",
        action_params={
            "flow_id": flow.flow_id
        })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ingress meta rule on %s" % ingress_sw.name)
        logging.debug("Installed ingress meta rule on %s" % ingress_sw.name)
    
    
    def writeFlowRules(self, ingress_sw,flow):
    
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.flow_exact",
        match_fields={
            "hdr.ipv4.srcAddr": flow.saddr,
            "hdr.tcp.srcPort":  flow.sport,
            "hdr.ipv4.dstAddr": flow.daddr,
            "hdr.tcp.dstPort":  flow.dport,
            "hdr.ipv4.protocol": flow.proto
        },
        action_name="MyIngress.update_stats",
        action_params={
            "flow_id": flow.flow_id
        })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ingress flow rule on %s" % ingress_sw.name)
        logging.debug("Installed ingress flow rule on %s" % ingress_sw.name)
    
    
    def writeIPForwardRules(self, ingress_sw,
                            dst_eth_addr, dst_ip_addr, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_eth_addr,
                "port" : out_port
            })
        ingress_sw.WriteTableEntry(table_entry)
        print("Installed ingress rule on %s" % ingress_sw.name)
        logging.debug("Installed ingress rule on %s" % ingress_sw.name)
    
    def readTableRules(self, sw):
        """
        Reads the table entries from all tables on the switch.
    
        :param p4info_helper: the P4Info helper
        :param sw: the switch connection
        """
        print('\n----- Reading tables rules for %s -----' % sw.name)
        logging.debug('\n----- Reading tables rules for %s -----' % sw.name)
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = self.p4info_helper.get_tables_name(entry.table_id)
                print('%s: ' % table_name)
                logging.debug('%s: ' % table_name)
                for m in entry.match:
                    print(self.p4info_helper.get_match_field_name(table_name, m.field_id))
                    logging.debug(self.p4info_helper.get_match_field_name(table_name, m.field_id))
                    print('%r' % (self.p4info_helper.get_match_field_value(m),))
                    logging.debug('%r' % (self.p4info_helper.get_match_field_value(m),))
                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                print("->", action_name)
                logging.debug("->{}".format(action_name))
                for p in action.params:
                    print(self.p4info_helper.get_action_param_name(action_name, p.param_id))
                    logging.debug(self.p4info_helper.get_action_param_name(action_name, p.param_id))
                    print('%r' % p.value)
                    logging.debug('%r' % p.value)
    
    
    def printCounter(self, sw, counter_name, index):
        """
        Reads the specified counter at the specified index from the switch. In our
        program, the index is the tunnel ID. If the index is 0, it will return all
        values from the counter.
    
        :param p4info_helper: the P4Info helper
        :param sw:  the switch connection
        :param counter_name: the name of the counter from the P4 program
        :param index: the counter index (in our case, the tunnel ID)
        """
        counters = list()
        for response in sw.ReadCounters(self.p4info_helper.get_counters_id(counter_name), index):
            for entity in response.entities:
                counter = entity.counter_entry
                #print("%s %s %d: %d packets (%d bytes)" % (
                #    sw.name, counter_name, index,
                #    counter.data.packet_count, counter.data.byte_count
                #))
                logging.debug("%s %s %d: %d packets (%d bytes)" % (
                    sw.name, counter_name, index,
                    counter.data.packet_count, counter.data.byte_count
                ))

                counters.append(counter.data.packet_count)
        return counters[0]


    def verify_new_flow(self, flow):
        res = False
        for f in self.flows.values():
            if f.compare_flow(flow) and f.crash_flow():
                res = True 
                break
        return res

    def install_proactive_rule(self, flow):
        backup_addr = self.backup[flow.daddr]
        start = self.topo[flow.saddr]["sw"]
        end = self.topo[backup_addr]["sw"]
        path = self.get_switch_path_from_flow(start, end, list())
        logging.debug("Path for adding proactive flow {}".format([sw.name for sw in path]))
        #TODO get all connection to the crash server
        print("Path for adding proactive flow {}".format([sw.name for sw in path]))
        for i, sw in enumerate(path):
            if i != 0:
                self.writeBackUpInitRules(sw, flow.saddr, backup_addr,
                flow.dport)
            else:
                self.writeBackUpInitFirstRules(sw, flow.saddr, backup_addr, flow.dport)

            self.writeBackUpRules(sw, backup_addr, flow.saddr, flow.dport) 

    def remove_proactive_rule(self, flow):
        start = self.topo[flow.saddr]["sw"]
        end = self.topo[flow.daddr]["sw"]
        path = self.get_switch_path_from_flow(start, end, list())
        logging.debug("Path for removing proactive flow {}".format([sw.name for sw in path]))
        print("Path for removing proactive flow {}".format([sw.name for sw in path]))
        for i, sw in enumerate(path):
            if i != 0:
                self.deleteBackUpInitRules(sw, flow.saddr, flow.daddr,
                flow.dport)
            else:
                self.deleteBackUpInitFirstRules(sw, flow.saddr, flow.daddr, flow.dport)

            self.deleteBackUpRules(sw, flow.daddr, flow.saddr, flow.dport) 

        
    def handle_flow_request(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        server_address = (self.ip, self.port)
        sock.bind(server_address)
        
        while True:
            data, address = sock.recvfrom(4096)
            if data:
                self.lock.acquire()
                new_flow = pickle.loads(data)
                print("Request for new flow: {}".format(new_flow))
                logging.debug("Request for new flow: {}".format(new_flow))

                if new_flow in self.flows_id:
                    print("Flow already exist")
                    logging.debug("Flow already exist")
                    #TODO Verify number of retransmission on switch
                    f = self.flows_id[new_flow]
                    f = self.flows[f]
                    f.retrans = True
                    self.install_proactive_rule(f)
                    sock.sendto("{}-{}".format(f.flow_id, new_flow), address)

                elif self.verify_new_flow(new_flow): 
                    print("Creating new flow")
                    logging.debug("Creating new flow")
                    new_flow.flow_id = self.flow_id 
                    self.flows[self.flow_id] = new_flow
                    self.flows_id[new_flow] = self.flow_id
                    self.flow_id += 1
                    new_flow_rev = self.create_flow(new_flow.daddr, new_flow.dport,
                                                    new_flow.saddr, new_flow.sport, 
                                                    new_flow.proto)

                    #TODO test flow information

                    start = self.topo[new_flow.saddr]["sw"]
                    end = self.topo[new_flow.daddr]["sw"]
                    path = self.get_switch_path_from_flow(start, end, list())
                    print("Path for new flow {}".format([sw.name for sw in path]))
                    logging.debug("Path for new flow {}".format([sw.name for sw in path]))

                    for sw in path:
                        self.writeFlowRules(sw, new_flow)
                        self.writeFlowRules(sw, new_flow_rev)
                        self.writeMetaRules(sw, new_flow)
                        self.writeMetaRules(sw, new_flow_rev)
                        self.map_switches_flows[sw].append(new_flow.flow_id)
                        self.map_switches_flows[sw].append(new_flow_rev.flow_id)
                        self.map_flow_retrans[new_flow.flow_id] = (0, False)
                        self.map_flow_retrans[new_flow_rev.flow_id] = (0, False)

                    sock.sendto("{}-{}".format(new_flow.flow_id, new_flow), address)
                    self.remove_proactive_rule(new_flow)

                    
                else:
                    print("Invalid flow, not installed")
                    logging.debug("Invalid flow, not installed")
                    sock.sendto("-1", address)
                self.lock.release()

        sock.close()
                    
                
    def add_mirror(self, port, cmd): 
        os.system("sudo simple_switch_CLI --thrift-port={} < {}".format(port, cmd))
    
    def start(self):
        # Instantiate a P4Runtime helper from the p4info file
    
        try:
            # Create a switch connection object for s1 and s2;
            # this is backed by a P4Runtime gRPC connection.
            # Also, dump all P4Runtime messages sent to switch to given txt files.
            s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s1',
                address='127.0.0.1:50051',
                device_id=0,
                proto_dump_file='logs/s1-p4runtime-requests.txt')
            s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s2',
                address='127.0.0.1:50052',
                device_id=1,
                proto_dump_file='logs/s2-p4runtime-requests.txt')
            s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name='s3',
                address='127.0.0.1:50053',
                device_id=2,
                proto_dump_file='logs/s3-p4runtime-requests.txt')

            # Add mirror for server
            self.add_mirror(9090, "cmd_s1.txt")
            self.add_mirror(9091, "cmd_s2.txt")
    
            # Send master arbitration update message to establish this controller as
            # master (required by P4Runtime before performing any other write operation)
            s1.MasterArbitrationUpdate()
            s2.MasterArbitrationUpdate()
            s3.MasterArbitrationUpdate()

            #Topology info

            client_port = 3333
            server_port = 1234

            self.topo = {
                        "10.0.1.1": 
                        {
                            "mac": "08:00:00:00:01:11",
                            "sw" : s1,
                            "sw_port": 1
                        },
                        "10.0.2.2":
                        {
                            "mac": "08:00:00:00:02:22",
                            "sw" : s2,
                            "sw_port": 1
                        },
                        "10.0.2.3":
                        {
                            "mac": "08:00:00:00:02:44",
                            "sw" : s2,
                            "sw_port": 2
                        },
                        "10.0.3.3":
                        {
                            "mac": "08:00:00:00:03:33",
                            "sw" : s3,
                            "sw_port": 1
                        }
                    }

            self.links = {s1 : [s2, s3], s2:[s1, s3], s3:[s1, s2]}
            
            #MTU    
            h1_mac = "08:00:00:00:01:11"
            h1_ip = "10.0.1.1"

            #PLC
            h2_mac = "08:00:00:00:02:22"
            h2_ip = "10.0.2.2"

            h3_mac = "08:00:00:00:02:23"
            h3_ip = "10.0.2.3"

            #IDS
            ids_mac = "08:00:00:00:03:33"
            ids_ip = "10.0.3.3"
            
    
            # Install the P4 program on the switches
            s1.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on s1")
            logging.debug("Installed P4 Program using SetForwardingPipelineConfig on s1")
            s2.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on s2")
            logging.debug("Installed P4 Program using SetForwardingPipelineConfig on s2")
    
            s3.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on s3")
            logging.debug("Installed P4 Program using SetForwardingPipelineConfig on s3")

            self.lock.acquire()
    
            # Write the rules that tunnel traffic from h1 to h2
            f1 = self.create_flow(h1_ip, client_port, h2_ip, server_port, 6)
            self.writeFlowRules(s1, f1)

            f2 = self.create_flow(h2_ip, server_port, h1_ip, client_port, 6)
            self.writeFlowRules(s1, f2)
    
            self.writeIPForwardRules(s1, h1_mac, h1_ip, SWITCH_TO_HOST_PORT)
            self.writeIPForwardRules(s1, h2_mac, h2_ip, S1_S2_PORT)
            self.writeIPForwardRules(s1, h3_mac, h3_ip, S1_S2_PORT)
            self.writeIPForwardRules(s1, ids_mac, ids_ip, S1_S3_PORT)

            self.writeIDSClearRules(s1, SRTAGIDS_TYPE, h1_ip,
                                    h1_mac, SWITCH_TO_HOST_PORT)
    
            self.writeMetaRules(s1, f1)
            self.writeMetaRules(s1, f2)
            self.writeCloneRules(s1, h1_ip)
    
            #writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=100,
            #                 dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")
    
            # Write the rules that tunnel traffic from h2 to h1
            self.writeFlowRules(s2, f1)
            self.writeFlowRules(s2, f2)
    
            self.writeIPForwardRules(s2, h1_mac, h1_ip, S2_S1_PORT)
            self.writeIPForwardRules(s2, h2_mac, h2_ip, SWITCH_TO_HOST_PORT)
            self.writeIPForwardRules(s2, h3_mac, h3_ip, SWITCH_TO_HOST_PORT_MUL)
            self.writeIPForwardRules(s2, ids_mac, ids_ip, S2_S3_PORT)
    
            self.writeIDSClearRules(s2, SRTAGIDS_TYPE, h2_ip,
                                    h2_mac, SWITCH_TO_HOST_PORT)
            self.writeIDSClearRules(s2, SRTAGIDS_TYPE, h3_ip,
                                    h3_mac, SWITCH_TO_HOST_PORT_MUL)
            self.writeMetaRules(s2, f1)
            self.writeMetaRules(s2, f2)
            self.writeCloneRules(s2, h2_ip)
            self.writeCloneRules(s2, h3_ip)
    
            self.writeIPForwardRules(s3, h1_mac, h1_ip, S3_S1_PORT)
            self.writeIPForwardRules(s3, h2_mac, h2_ip, S3_S2_PORT)
            self.writeIPForwardRules(s3, h3_mac, h3_ip, S3_S2_PORT)
            self.writeIPForwardRules(s3, ids_mac, ids_ip, SWITCH_TO_HOST_PORT)
            #writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=200,
            #                 dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1")

            self.writeRedirectRules(s1, SRTAG_TYPE, S1_S3_PORT) 
            self.writeRedirectRules(s2, SRTAG_TYPE, S2_S3_PORT) 
            self.writeLastRedirectRules(s3, SRTAG_TYPE, ids_mac, SWITCH_TO_HOST_PORT) 
            self.writeIDSVerificationRules(s3, h1_ip, SWITCH_TO_HOST_PORT, S3_S1_PORT)
            self.writeIDSVerificationRules(s3, h2_ip, SWITCH_TO_HOST_PORT, S3_S2_PORT)
            self.writeIDSVerificationRules(s3, h3_ip, SWITCH_TO_HOST_PORT, S3_S2_PORT)
            self.writeCloneRules(s3, ids_ip)
    
            # TODO Uncomment the following two lines to read table entries from s1 and s2
            #self.readTableRules(s1)
            #self.readTableRules(s2)
            #self.readTableRules(s3)
            # Print the tunnel counters every 2 seconds
            self.map_switches_flows = {s1: [1, 2], s2: [1, 2], s3: []}
            # flow_id -> nbr_retran, backup_installed
            self.map_flow_retrans = {1: (0, False), 2:(0, False)}
            flow_terminated = set()

            self.lock.release()
    
            while True:
                sleep(1)
                #print('\n----- Reading counters Retransmission -----')
                logging.debug('\n----- Reading counters Retransmission -----')
                for k, v in self.map_switches_flows.items():
                    for flow_id in v:
                        nb_terminated = self.printCounter(k,
                                                    "MyIngress.terminatedCount", flow_id)
                        if nb_terminated > 0:
                            flow = self.flows[flow_id]
                            flow.is_terminated = True
                            flow_terminated.add(flow_id)
                            
    
                        nb_retrans = self.printCounter(k,
                                               "MyIngress.retransCount", flow_id)
                        if nb_retrans > 0:
                            flow = self.flows[flow_id]
                            flow.nb_retrans += 1

                            
        except KeyboardInterrupt:
            print(" Shutting down.")
            logging.debug(" Shutting down.")
        except grpc.RpcError as e:
            logging.error(printGrpcError(e))
            printGrpcError(e)
    
        ShutdownAllSwitchConnections()

    def run(self):
        #TODO ADD lock
        #t1 = threading.Thread(target=self.start, daemon=True)
        t1 = threading.Thread(target=self.handle_flow_request)
        t1.setDaemon(True)
        t1.start()
        self.start()
        #t2.start()
        #t1.join()
        #t2.join()
    
if __name__ == '__main__':
    logging.basicConfig(filename="logs/controller.log", encoding="utf-8", level=logging.DEBUG)

    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/basic.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    backup = {"10.0.2.2" : "10.0.2.3"}
    controller = Controller("172.0.10.2", 3000, backup, args.p4info, args.bmv2_json)
    controller.run()
