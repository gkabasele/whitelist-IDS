import socket
import sys
import pickle
import threading
from netfilterqueue import NetfilterQueue

from mycontroller import Flow

from scapy.all import *

flows_requested = set()

lock = threading.Lock()

def threading_sending(ip, port, flow, lock):
    lock.acquire()
    flow_rev = Flow(flow.daddr, flow.dport, flow.saddr,
                    flow.sport, flow.proto)

    if (flow not in flows_requested
        and flow_rev not in flows_requested):

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (ip, port)
        #server_address = ("172.0.10.2", 3000)

        try:
            print("Sending {}".format(flow))
            flow = pickle.dumps(flow)
            sent = sock.sendto(flow, server_address) 
            print("Waiting response")
            data, address = sock.recvfrom(4096)
            print("Flow created with id : {}".format(data))
            flows_requested.add(flow)    
            flows_requested.add(flow_rev)    
        finally:
            sock.close()
    else:
            print("Flow already exists")
    lock.release()


def print_and_accept(packet):
    pkt = IP(packet.get_payload())
    if IP in pkt and TCP in pkt:
        saddr = pkt[IP].src
        daddr = pkt[IP].dst
        sport = pkt[TCP].sport  
        dport = pkt[TCP].dport 
        proto = 6
        flow = Flow(saddr, sport, daddr, dport, proto)
        print(flow)    
    

    packet.accept()

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

def send_request(packet):
    pkt = IP(packet.get_payload())

    if IP in pkt and TCP in pkt:
        saddr = pkt[IP].src
        daddr = pkt[IP].dst
        sport = pkt[TCP].sport  
        dport = pkt[TCP].dport 
        proto = 6
        flow = Flow(saddr, sport, daddr, dport, proto)
        flow_rev = Flow(daddr, dport, saddr, sport, proto)
        t = threading.Thread(target=threading_sending, args=("172.0.10.2", 3000, flow, lock))
        t.start()

    packet.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, send_request)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print(" ")

nfqueue.unbind()
