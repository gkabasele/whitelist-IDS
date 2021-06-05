import socket
import sys
import pickle
import threading
import copy
import logging
from netfilterqueue import NetfilterQueue

from mycontroller import Flow

from scapy.all import *

class SRTag(Packet):
    name = "SRTag"
    fields_desc=[ IPField("dst", None),
                  ShortField("identifier", None),
                  ByteField("protocol", None),
                  ByteField("reason", None)
                ]


SRTAG = "SRTag"
flows_requested = set()
flows = set()
flows_mul_req = dict()

lock = threading.Lock()

def is_new_flow(flow, flow_rev):
    return flow not in flows_requested and flow_rev not in flows_requested

# A flow that have been seen multiple time and has not been accepted
def is_attempting_flow(flow, flow_rev):
    return ((flow not in flows_mul_req or flows_mul_req[flow] < 3) 
            and (flow_rev not in flows_mul_req or flows_mul_req[flow_rev] < 3))

def is_candidate_flow(flow, flow_rev):
    return is_new_flow(flow, flow_rev) and is_attempting_flow(flow, flow_rev) 

def threading_sending(ip, port, flow, lock):
    lock.acquire()
    flow_rev = Flow(flow.daddr, flow.dport, flow.saddr,
                    flow.sport, flow.proto)

    #if (flow not in flows_requested
    #    and flow_rev not in flows_requested):

    if is_candidate_flow(flow, flow_rev):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = (ip, port)
        #server_address = ("172.0.10.2", 3000)

        try:
            print("Sending {}".format(flow))
            logging.debug("Sending {}".format(flow))
            flow_data = pickle.dumps(flow)
            sent = sock.sendto(flow_data, server_address) 
            print("Waiting response")
            logging.debug("Waiting response")
            data, address = sock.recvfrom(4096)
            if data != "-1":
                print("Flow created with id : {}".format(data))
                logging.debug("Flow created with id : {}".format(data))
                flows_requested.add(flow)    
                flows_requested.add(flow_rev)    
                flows.add(flow)
                flows.add(flow_rev)
            else:
                if flow in flows_mul_req:
                    flows_mul_req[flow] += 1
                else:
                    print("Multiple requester for {}".format(flow))
                    logging.debug("Multiple requester for {}".format(flow))
                    flows_mul_req[flow] = 1
                
        finally:
            sock.close()
    else:
            print("Flow {} has already been requested".format(flow))
            logging.debug("Flow {} has already been requested".format(flow))
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

def strip_tag(packet):
    orig_proto = packet[SRTAG].protocol
    orig_daddr = packet[SRTAG].dst 
    payload = packet.getlayer(SRTAG).payload
    packet.getlayer(IP).remove_payload()
    packet[IP].proto = orig_proto 
    packet[IP].dst = orig_addr
    pacekt[IP].chksum = 0 # with 0 the checksum is recomputed
    new_p = Ether()/packet[IP]/payload
    return new_p

def send_request(packet):
    print(packet)
    pkt = IP(packet.get_payload())
    logging.debug(packet)
    drop = False

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
        t.join()
        drop = flow in flows
    if not drop:
        packet.accept()
    else:
        packet.drop()

f1 = Flow("10.0.1.1", 3333, "10.0.2.2", 1234, 6)
f2 = Flow("10.0.2.2", 1234, "10.0.1.1", 3333, 6)
flows.add(f1)
flows.add(f2)

logging.basicConfig(filename="logs/ids.log", encoding="utf-8", level=logging.DEBUG)
nfqueue = NetfilterQueue()
nfqueue.bind(1, send_request)
try:
    nfqueue.run()
except KeyboardInterrupt:
    logging.debug("Ending")
    print(" ")

nfqueue.unbind()
