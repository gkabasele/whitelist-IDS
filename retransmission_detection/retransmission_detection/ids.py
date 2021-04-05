import socket
import sys
import pickle

from my_controller import Flow

from scapy.all import *

flows_requested = set()

def send_request(pkt):

    if IP in pkt and TCP in pkt:
        saddr = pkt[IP].src
        daddr = pkt[IP].src
        sport = pkt[TCP].sport  
        dport = pkt[TCP].dport 
        proto = 6
        flow = Flow(saddr, sport, daddr, dport, proto)
        flow_rev = Flow(daddr, dport, saddr, sport, proto)
        if flow not in flows_requested and flow_rev not in flows_requested:
            flows_requested.add(flow)    
            flows_requested.add(flow_rev)    
            flow = pickle.dumps()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_address = ("localhost", 3000)

            try:
                print("Sending {}".format(flow))
                sent = sock.sendto(message, server_address) 
                print("Waiting response")
                received = sock.revcfrom(4096)
                print("Flow created with id : {}".format(received))
            finally:
                sock.close()
        else:
            print("Flow already exists")
    
sniff(filter="ip", prn=send_request)
