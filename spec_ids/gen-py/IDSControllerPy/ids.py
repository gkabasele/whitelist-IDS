#!/usr/bin/env python

import sys
import re
import collections
import argparse
import yaml
import Controller
import time

from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct import *
from netaddr import IPAddress
from utils import *

from logging import FileHandler
from logging import Formatter

from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol
from ttypes import *
from stateCompute import State

parser = argparse.ArgumentParser()
parser.add_argument('--ip', action='store', dest='ip', default='172.0.10.2')
parser.add_argument('--port', action='store', dest='port', type=int, default=2050)
parser.add_argument('--strategy', action='store', dest='strategy', choices=['critical', 'normal'], default='critical')
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

CRIT = 'critical'
NORMAL = 'normal'

# Initialization of the log
LOG_FORMAT = ("[%(asctime)s] [%(levelname)s]:%(message)s")
LOG_LEVEL = logging.DEBUG
IDS_SPEC_FILE = "logs/ids_spec.log"
logger = logging.getLogger('__name__')
logger.setLevel(LOG_LEVEL)
handler = FileHandler(IDS_SPEC_FILE)
handler.setLevel(LOG_LEVEL)
handler.setFormatter(Formatter(LOG_FORMAT))
logger.addHandler(handler)

class PacketHandler():

    def __init__(self, varfile, strategy, update_duration=120):
        # var to name
        self.var = {}
        # (transId,ip) to var
        self.transId = {}

        # check if var has been updated
        self.var_update = {}

        self.client = None
        self.transport = None
        self.strategy = strategy
        #self.setup_controlplane_connection(host, port)
        self.create_variables(varfile)
        self.update_duration = update_duration
        self.last_update = None

        self.state_store = State(varfile)

    #def setup_controlplane_connection(self, host, port): 
    #    socket = TSocket.TSocket(host, port)
    #    self.transport = TTransport.TBufferedTransport(socket)
    #    protocol = TBinaryProtocol.TBinaryProtocol(self.transport)
    #    self.client = Controller.Client(protocol)
    #    self.transport.open()


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
            # use to detect when a variable has been updated
            self.var_update[var['name']] = False
 
    def print_and_accept(self, packet):
        payload = packet.get_payload()
        pkt = IP(payload)
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
                    logger.info("Request {} has been send to {}".format(transId, dstip))
                    self.transId[(transId, dstip)] =  ProcessVariable(dstip, dport, kind, addr)
                else:
                    # Receive request
                    transId = pkt[ModbusRes].transId
                    logger.info("Response from {} for request {}".format(srcip, transId))
                    name = self.var[self.transId[(transId, srcip)]]
                    self.state_store.update_var_from_packet(
                                                name,
                                                pkt[ModbusRes].funcode,
                                                pkt[ModbusRes].payload)
                    self.var_update[name] = True
                    logger.info("Process variable: {}".format(self.var_update))
                    # Use timer
                    if (all(x for x in self.var_update.values()) or
                       (self.last_update is not None and
                        time.time() - self.last_update > self.update_duration)):
                        if self.strategy == CRIT:
                            i, dist = self.state_store.get_min_distance()
                        elif self.strategy == NORMAL:
                            i, dist = self.state_store.get_max_distance()
                        self.last_update = time.time()
                        logger.info("ID: {} Dist: {}".format(i, dist))
                        for k in self.var_update:
                            self.var_update[k] = False
        packet.drop()

    def close(self):
        pass


def main():

    nfqueue = NetfilterQueue()
    handler = PacketHandler(varfile, args.strategy)
    nfqueue.bind(2, handler.print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print "Done"
    handler.close()
    nfqueue.unbind()

if __name__ == '__main__':
    main()
