#!/usr/bin/env python2
import argparse
import grpc
import os
import threading
import socket
import pickle
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

class Flow(object):

    def __init__(self, saddr, sport, daddr, dport, proto, flow_id=None):
        self.saddr = saddr
        self.sport = sport
        self.daddr = daddr
        self.dport = dport
        self.proto = proto
        self.flow_id = flow_id
    
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

class Controller(object):

    def __init__(self, ip, port, p4info_file_path, bmv2_file_path):

        self.flows = dict()
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

    def create_flow(self, saddr, sport, daddr, dport, proto):
        f = Flow(saddr, sport, daddr, dport, proto, self.flow_id)
        if self.flow_id not in self.flows:
            self.flows[self.flow_id] = f
        else:
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

    def writeRedirectRules(self, sw, etherType, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.srtag_exact",
        match_fields={
            "hdr.ethernet.etherType": etherType
        },
        action_name="MyIngress.srtag_forward",
        action_params={
            "port": out_port 
        })
        sw.WriteTableEntry(table_entry)
        print("Install redirection rule on %s" % sw.name)
        
    def writeLastRedirectRules(self, sw, etherType, out_port):
        table_entry = self.p4info_helper.buildTableEntry(
        table_name="MyIngress.srtag_exact",
        match_fields={
            "hdr.ethernet.etherType": etherType
        },
        action_name="MyIngress.change_to_ip_and_forward",
        action_params={
            "port": out_port 
        })
        sw.WriteTableEntry(table_entry)
        print("Install redirection rule on %s" % sw.name)
    
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
    
    def readTableRules(self, sw):
        """
        Reads the table entries from all tables on the switch.
    
        :param p4info_helper: the P4Info helper
        :param sw: the switch connection
        """
        print('\n----- Reading tables rules for %s -----' % sw.name)
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = self.p4info_helper.get_tables_name(entry.table_id)
                print('%s: ' % table_name)
                for m in entry.match:
                    print(self.p4info_helper.get_match_field_name(table_name, m.field_id))
                    print('%r' % (self.p4info_helper.get_match_field_value(m),))
                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                print("->", action_name)
                for p in action.params:
                    print(self.p4info_helper.get_action_param_name(action_name, p.param_id))
                    print('%r' % p.value)
    
    
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
                print("%s %s %d: %d packets (%d bytes)" % (
                    sw.name, counter_name, index,
                    counter.data.packet_count, counter.data.byte_count
                ))
                counters.append(counter.data.packet_count)
        return counters[0]
    
    
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
                new_flow.flow_id = self.flow_id 
                self.flow_id += 1
                new_flow_rev = self.create_flow(new_flow.daddr, new_flow.dport,
                                                new_flow.saddr, new_flow.sport, 
                                                new_flow.proto)

                #TODO test flow information

                start = self.topo[new_flow.saddr]["sw"]
                end = self.topo[new_flow.daddr]["sw"]
                path = self.get_switch_path_from_flow(start, end, list())
                print("Path for new flow {}".format([sw.name for sw in path]))

                #self.writeIPForwardRules(start, self.topo[new_flow.saddr]["mac"],
                #                         new_flow.saddr, self.topo[new_flow.saddr]["sw_port"])

                #self.writeIPForwardRules(end, self.topo[new_flow.daddr]["mac"],
                #                         new_flow.daddr, self.topo[new_flow.daddr]["sw_port"])

                for sw in path:
                    self.writeFlowRules(sw, new_flow)
                    self.writeFlowRules(sw, new_flow_rev)
                    self.writeMetaRules(sw, new_flow)
                    self.writeMetaRules(sw, new_flow_rev)
                    self.map_switches_flows[sw].append(new_flow.flow_id)
                    self.map_switches_flows[sw].append(new_flow_rev.flow_id)
                    self.map_flow_retrans[new_flow.flow_id] = (0, False)
                    self.map_flow_retrans[new_flow_rev.flow_id] = (0, False)
                    self.readTableRules(sw) 

                sock.sendto("{}".format(new_flow.flow_id), address)
                self.lock.release()

        sock.close()
                    
                
    
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

            h3_mac = "08:00:00:00:02:44"
            h3_ip = "10.0.2.3"

            #IDS
            ids_mac = "08:00:00:00:03:33"
            ids_ip = "10.0.3.3"
            
    
            # Install the P4 program on the switches
            s1.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on s1")
            s2.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on s2")
    
            s3.SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                           bmv2_json_file_path=self.bmv2_file_path)
            print("Installed P4 Program using SetForwardingPipelineConfig on s3")

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
    
            self.writeMetaRules(s1, f1)
            self.writeMetaRules(s1, f2)
    
            #writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s2, tunnel_id=100,
            #                 dst_eth_addr="08:00:00:00:02:22", dst_ip_addr="10.0.2.2")
    
            # Write the rules that tunnel traffic from h2 to h1
            self.writeFlowRules(s2, f1)
            self.writeFlowRules(s2, f2)
    
            self.writeIPForwardRules(s2, h1_mac, h1_ip, S2_S1_PORT)
            self.writeIPForwardRules(s2, h2_mac, h2_ip, SWITCH_TO_HOST_PORT)
            self.writeIPForwardRules(s2, h3_mac, h3_ip, SWITCH_TO_HOST_PORT_MUL)
            self.writeIPForwardRules(s2, ids_mac, ids_ip, S2_S3_PORT)
    
            self.writeMetaRules(s2, f1)
            self.writeMetaRules(s2, f2)
    
            self.writeIPForwardRules(s3, h1_mac, h1_ip, S3_S1_PORT)
            self.writeIPForwardRules(s3, h2_mac, h2_ip, S3_S2_PORT)
            self.writeIPForwardRules(s3, h3_mac, h3_ip, S3_S2_PORT)
            self.writeIPForwardRules(s3, ids_mac, ids_ip, SWITCH_TO_HOST_PORT)
            #writeTunnelRules(p4info_helper, ingress_sw=s2, egress_sw=s1, tunnel_id=200,
            #                 dst_eth_addr="08:00:00:00:01:11", dst_ip_addr="10.0.1.1")

            self.writeRedirectRules(s1, SRTAG_TYPE, S1_S3_PORT) 
            self.writeRedirectRules(s2, SRTAG_TYPE, S2_S3_PORT) 
            self.writeLastRedirectRules(s3, SRTAG_TYPE, SWITCH_TO_HOST_PORT) 
    
            # TODO Uncomment the following two lines to read table entries from s1 and s2
            self.readTableRules(s1)
            self.readTableRules(s2)
            self.readTableRules(s3)
            # Print the tunnel counters every 2 seconds
            self.map_switches_flows = {s1: [1, 2], s2: [1, 2], s3: []}
            # flow_id -> nbr_retran, backup_installed
            self.map_flow_retrans = {1: (0, False), 2:(0, False)}
            flow_terminated = list()

            self.lock.release()
    
            while True:
                sleep(2)
                '''
                print '\n----- Reading counters -----'
                printCounter(p4info_helper, s1, "MyIngress.ingressPktStats", 1)
                printCounter(p4info_helper, s2, "MyIngress.ingressPktStats", 2)
                '''
    
                print('\n----- Reading counters Retransmission -----')
                for k, v in self.map_switches_flows.items():
                    for flow_id in v:
                        nb_terminated = self.printCounter(k,
                                                    "MyIngress.terminatedCount", flow_id)
                        if nb_terminated > 0:
                            flow_terminated.append(flow_id)
    
                        nb_retrans = self.printCounter(k,
                                               "MyIngress.retransCount", flow_id)
                        '''
                        flow = map_id_flow[flow_id]
                        backup_flow = flow.backup
                        if nb_retrans > 0 and backup_flow is not None:
                            new_id, new_id_rev = self.handle_retrans(p4info_helper, nb_retrans, 
                                                    map_flow_retrans, map_switches_flows,
                                                    flow_id, 2, map_id_backup_sw[flow_id], 
                                                    backup_flow)
                            if new_id != 0:
                                map_id_flow[new_id] = backup_flow
                                map_id_flow[new_id_rev] = backup_flow.get_rev()
                        '''
                '''
                printCounter(p4info_helper, s1, "MyIngress.retransCount", 1)   
                printCounter(p4info_helper, s1, "MyIngress.retransCount", 2)    
                printCounter(p4info_helper, s2, "MyIngress.retransCount", 1)   
                printCounter(p4info_helper, s2, "MyIngress.retransCount", 2)    
                '''
    
        except KeyboardInterrupt:
            print(" Shutting down.")
        except grpc.RpcError as e:
            printGrpcError(e)
    
        ShutdownAllSwitchConnections()

    def run(self):
        #TODO ADD lock
        t1 = threading.Thread(target=self.start)
        t2 = threading.Thread(target=self.handle_flow_request)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    
if __name__ == '__main__':
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

    controller = Controller("10.0.2.15",3000, args.p4info, args.bmv2_json)
    controller.run()
