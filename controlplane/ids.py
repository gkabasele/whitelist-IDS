import socket
import sys
import argparse
import json
import cPickle as pickle

from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct  import *
from netaddr import  IPAddress
from utils import *

# TAG MISS
IP_MISS = '10'
PORT_MISS = '20'
FUN_MISS = '30'
PAYLOAD_SIZE_MISS = '40'

# Code for request/response
OK = 1
ERROR = 2

parser = argparse.ArgumentParser()
parser.add_argument('--ip', action='store', dest='ip', default= '172.0.10.2',help='ip address of the controller') 
parser.add_argument('--port', action='store', dest='port', type=int ,default= 2000,help='ip address of the controller') 
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = (args.ip, args.port)
sock.connect(server)

packets = {}

bind_layers(IP, SRTag, proto=200)
bind_layers(SRTag, TCP, protocol=6)
bind_layers(TCP, Modbus, sport=5020)
bind_layers(TCP, Modbus, dport=5020)

def forge_new_packet(payload, dstip, proto):
    pkt = IP(payload)
    ip = pkt[IP]
    tcp = pkt[TCP]
    ip.dst = dstip
    ip.proto = proto
    return ip/tcp
     
def print_and_accept(packet):
    
    print(packet)
    payload = packet.get_payload()
    pkt = IP(payload)
    reason = pkt[SRTag].reason
    funcode = -1 
    dstip = pkt[SRTag].dst 
    srcip = pkt[IP].src
    sport = str(pkt[TCP].sport)
    dport = str(pkt[TCP].dport)
    proto = str(pkt[SRTag].protocol)
    length = str(len(pkt))
    if Modbus in pkt:
        funcode = str(pkt[Modbus].funcode)
    flow = FlowRequest(reason, srcip, sport, dstip, dport, proto, funcode, length)
    packets[flow.req_id] = payload
    try:
        # TODO check for error (decorator)
        Communication.send(flow,sock)
        msg = Communication.recv_msg(sock)
        print "Received response"
        if msg:
            resp = pickle.loads(msg)    
            if resp.code == OK:
                pkt = forge_new_packet(packets[flow.req_id], dstip, proto)
                send(pkt)
            elif resp.code == ERROR:
                print "an error occurred (code: %d)" % code 
            else:
                pass
    finally: 
        packet.accept()

def main(): 
    
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print "Done"
    
    nfqueue.unbind()

if __name__ == '__main__':
        main()
        sock.close()
