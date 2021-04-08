import socket
import sys
import pickle
from netfilterqueue import NetfilterQueue

from mycontroller import Flow

from scapy.all import *

flows_requested = set()

def never_respond():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.out_interface = "eth0"
    rule.dst = "10.0.0.0/255.255.0.0"
    rule.protocol = "tcp"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)

    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.out_interface = "eth0"
    rule.dst = "10.0.0.0/255.255.0.0"
    rule.protocol = "udp"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)

def print_and_accept(pkt):
    print(pkt)
    print(pkt.get_payload_len())
    pkt.accept()

def test_flow(saddr, sport, daddr, dport, proto):
    flow = pickle.dumps(Flow(saddr, sport, daddr, dport, proto))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = ("172.0.10.2", 3000)

    try:
        print("Sending " + str(flow))
        sent = sock.sendto(flow, server_address) 
        print("Waiting response")
        received = sock.recvfrom(4096)
        print("Flow created with id : {}".format(received))
    finally:
        sock.close()

def send_request(pkt):

    if IP in pkt and TCP in pkt:
        saddr = pkt[IP].src
        daddr = pkt[IP].src
        sport = pkt[TCP].sport  
        dport = pkt[TCP].dport 
        proto = 6
        flow = Flow(saddr, sport, daddr, dport, proto)
        flow_rev = Flow(daddr, dport, saddr, sport, proto)
        if (flow not in flows_requested
            and flow_rev not in flows_requested):

            flows_requested.add(flow)    
            flows_requested.add(flow_rev)    
            flow = pickle.dumps(flow)

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_address = ("172.0.10.1", 3000)

            try:
                print("Sending {}".format(flow))
                sent = sock.sendto(flow, server_address) 
                print("Waiting response")
                received = sock.recvfrom(4096)
                print("Flow created with id : {}".format(received))
            finally:
                sock.close()
        else:
            print("Flow already exists")

#test_flow("10.0.1.1",3000, "10.0.2.3", 3344, 6)    

#sniff(iface="eth0", filter="ip", prn=send_request)

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print(" ")

nfqueue.unbind()
