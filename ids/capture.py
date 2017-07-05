import socket
import sys
import argparse
import json

from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct  import *
from netaddr import  IPAddress

parser = argparse.ArgumentParser()
parser.add_argument('--ip', action='store', dest='ip', default= '172.0.10.2',help='ip address of the controller') 
parser.add_argument('--port', action='store', dest='port', type=int ,default= 2000,help='ip address of the controller') 
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = (args.ip, args.port)
sock.connect(server)

history = {}

class SRTag(Packet):
    name = "SRTagPacket"
    fields_desc=[ IPField("dst", None),
                  ShortField("identifier", 0),
                  ByteField("protocol", 6),
                  ByteField("reason", 0)
                ]
    

bind_layers(IP, SRTag, proto=200)
bind_layers(SRTag, TCP, protocol=6)

#TODO packet remove layer
def forge_new_packet(payload, dstip, proto):
    pkt = IP(payload[:-8])
    pkt[IP].dst = dstip
    pkt[IP].proto = proto
    return pkt
     
    

def print_and_accept(packet):
    
    print(packet)
    payload = packet.get_payload()
    pkt = IP(payload)
    dstip = pkt[SRTag].dst 
    srcip = pkt[IP].src
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    proto = pkt[SRTag].protocol
    flow = (srcip,sport,dstip,dport,proto)
    try:
        if flow not in history: 
            fail = sock.sendall(str(flow))
            if not fail:
                history[flow] = True
                resp = sock.recv(128)
                print "Received response", resp
                pkt = forge_new_packet(payload, dstip, proto)
                send(pkt)
                
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
