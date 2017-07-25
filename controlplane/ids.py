import socket
import ssl
import sys
import argparse
import json
import cPickle as pickle
import time

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

# Wrapper SSL
ssl_sock = ssl.wrap_socket(sock)                         
                            

server = (args.ip, args.port)
#sock.connect(server)
ssl_sock.connect(server)

packets = {}

bind_layers(IP, SRTag, proto=200)
bind_layers(SRTag, TCP, protocol=6)
bind_layers(TCP, Modbus, sport=5020)
bind_layers(TCP, Modbus, dport=5020)
bind_layers(Modbus, ModbusDiag, funcode=8)



def modify_layer(layer_name, layer_dict, value_dict ):
    #FIXME avoid eval
    layer = eval(layer_name+'()') 
    for field,value in layer_dict.iteritems():
        if field in value_dict:
            setattr(layer, field, value_dict[field])
        else:
            setattr(layer, field, layer_dict[field])
    return layer
    
    
def layer_to_dict(layer, pkt):
    field_names = [field.name for field in pkt[layer].fields_desc]
    fields = {field_name : getattr(pkt[layer], field_name) for field_name in field_names}
    return fields

def forge_packet(pkt, dstip, proto):
    ip_dict = layer_to_dict(IP, pkt) 
    ip = modify_layer('IP', ip_dict, {'dst' : dstip, 'proto': int(proto), 'len' : pkt[IP].len-8})
    tcp = pkt[TCP]
    return ip/tcp


def is_safe(pkt):

    m_sub = [4,1,10]
    # 253(PDU) + 7(MBAP) + 60(TCP max) + 60(max IP) + 8(SRTag)
    headers_size = (pkt[IP].ihl*4) + (pkt[TCP].dataofs*4) + 15
    safe = (len(pkt) <= (253 + headers_size ))
    if not safe:
        print "Packet too big"
    if ModbusDiag in pkt: 
        safe = (pkt[ModbusDiag].subfuncode not in m_sub)
        print "Malicious Modbus diagnostic function"

    # TODO check when excpetion for function code scan
    return safe
        
         
     
def print_and_accept(packet):
   
    print(packet)
    payload = packet.get_payload()
    pkt = IP(payload)
    print "Pkt Rcv: ", pkt.summary()
    srcip = pkt[IP].src
    dstip = pkt[SRTag].dst 
    reason = str(pkt[SRTag].reason)
    proto = str(pkt[SRTag].protocol)
    sport = str(pkt[TCP].sport)
    dport = str(pkt[TCP].dport)
    length = str(len(pkt)+6) # + 14 bytes for ethernet header - 8 bytes for SRTag
    funcode = str(pkt[Modbus].funcode) if Modbus in pkt else -1 
    identifier = str(pkt[SRTag].identifier)
    flow = FlowRequest(reason, srcip, sport, dstip, dport, proto, funcode, length, identifier)
    packets[flow.req_id] = pkt
    try:
        # TODO check for error 
        if is_safe(pkt):
            Communication.send(flow, ssl_sock)
            msg = Communication.recv_msg(ssl_sock)
            print "Received response"
            if msg:
                resp = pickle.loads(msg)    
                if resp.code == OK:

                    pkt = forge_packet(packets[resp.req_id], dstip, proto)
                    print pkt.summary()
                    send(pkt)
                elif resp.code == ERROR:
                    print "an error occurred"  
                else:
                    print "Unknown code"
        else:
            print "Malicious packet detected"
            flow.install = False
            Communication.send(flow, ssl_sock)
            msg = Communication.recv_msg(ssl_sock)
            print "Received response"
            if msg:
                resp = pickle.loads(msg)
                if resp.code == OK:
                    print "Flow: %s:%s -> %s:%s" % (srcip, sport, dstip, dport)
    finally: 
        packet.drop()

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
        ssl_sock.close()
