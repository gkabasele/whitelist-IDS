#!/usr/bin/env python

import sys
import re
import collections
import argparse
import yaml
import Controller

from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct import *
from netaddr import IPAddress
from utils import *

from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol
from ttypes import *
from stateCompute import State

parser = argparse.ArgumentParser()
parser.add_argument('--ip', action='store', dest='ip', default='172.0.10.2')
parser.add_argument('--port', action='store', dest='port', type=int, default=2050)
parser.add_argument('--varfile', action='store', dest='varfile', default='requirements.yml')

args = parser.parse_args()
host = args.ip
port = args.port
varfile = args.varfile

bind_layers(IP, SRTag, proto=200)
#bind_layers(SRTag, TCP, proto=6)
bind_layers(SRTag, TCP)
bind_layers(TCP, ModbusRes, sport=MODBUS_PORT)
bind_layers(TCP, ModbusReq, dport=MODBUS_PORT)

class PacketHandler():

    def __init__(self, varfile, host, port):
        # var to name
        self.var = {}
        # transId to var
        self.transId = {}
        self.client = None
        self.transport = None

        self.setup_controlplane_connection(host, port)
        self.create_variables(varfile)

        self.state_store = State(varfile)

    def setup_controlplane_connection(self, host, port): 
        socket = TSocket.TSocket(host, port)
        self.transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(self.transport)
        self.client = Controller.Client(protocol)
        self.transport.open()

    def create_variables(self, varfile):
        content = open(varfile).read()
        desc = yaml.load(content)
        for var_desc in desc['variables']:
            var = var_desc['variable']
            pv = ProcessVariable(var['host'],
                                 var['port'],
                                 var['type'],
                                 var['address'],
                                 var['size'],
                                 var['name']) 
            self.var[pv] = var['name']
 
    def print_and_accept(self, packet):
    
        print(packet)
        payload = packet.get_payload()
        pkt = IP(payload)
        print "Pkt Rcv: ", pkt.summary()
        srcip = pkt[IP].src
        dstip = pkt[SRTag].dst
        reason = pkt[SRTag].reason
        proto = pkt[SRTag].protocol
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        identifier = pkt[SRTag].identifier
        if (dport == MODBUS_PORT or sport == MODBUS_PORT):
            if reason == SRTAG_CLONE:
                if dport == MODBUS_PORT:
                    # Send request to controller 
                    switch = [identifier]
                    funcode = pkt[ModbusReq].funcode
                    transId = pkt[ModbusReq].transId
                    addr = pkt[ModbusReq].startAddr
                    kind = ProcessVariable.funcode_to_kind(funcode)
                    req = Flow(srcip, dstip, transId, dport, proto)
                    print "sending request"
                    self.transId[transId] =  ProcessVariable( dstip, dport, kind, addr) 
                    self.client.mirror(req, switch)
                else: 
                    # Receive request 
                    transId = pkt[ModbusRes].transId
                    self.state_store.update_var_from_packet(
                                                self.var[self.transId[transId]],
                                                pkt[ModbusRes].guess_payload_class())            
        packet.drop()

    def close(self):
        self.transport.close()


def main():

    nfqueue = NetfilterQueue()
    handler = PacketHandler(varfile, host, port)
    nfqueue.bind(2, handler.print_and_accept)

    try: 
        nfqueue.run()
    except KeyboardInterrupt:
        print "Done"
    handler.close()
    nfqueue.unbind()

if __name__=='__main__':
    main()
