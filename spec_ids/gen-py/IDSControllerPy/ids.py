import sys

from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct import *
from netaddr import IPAddress
from utils import *

from thrift.transport import TTransport
from thrift.transport import TSocket
from thrift.protocol import TBinaryProtocol

from IDSControllerPy import Controller
from IDSControllerPy.ttypes import *


parser = argparse.ArgumentParser()
parser.add_argument('--ip', action='store', dest='ip', default='172.0.10.2')
parser.add_argument('--port', action='store', dest='port', type=int, default=2050)
parser.add_argument('--varfile', action='store', dest='varfile', default='varphys.map')

args = parser.parse_args()
host = args.host
port = args.port
varfile = args.varfile

bind_layers(IP, SRTag, proto=200)
bind_layers(SRtag, TCP, proto=6)
bind_layers(TCP, ModbusRes, sport=MODBUS_PORT)
bind_layers(TCP, ModbusReq, dport=MODBUS_PORT)


socket = TSocket.TSocket(host, port)
transport = TTransport.TBufferedTransport(socket)
protocol = TBinaryProtocol.TBinaryProtocol(transport)
client = Controller.Client(protocol)
transport.open()

class PacketHandler():

    def __init__(self, varfile, host, port):
        # var to name
        self.var = {}
        # transId to var
        self.transId = {}
        self.client = None

        self.setup_controlplane_connection(host, port)
        self.create_variables(varfile)

    def setup_controlplane_connection(self, host, port): 
        socket = TSocket.TSocket(host, port)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        self.client = Controller.Client(protocol)
        transport.open()

    def create_variables(self, varfile):
        with open varfile as f:
            for line in f:
                varname = re.search('.+\[', line).group(0).strip('[')
                (ip, port, kind, addr, size) =  re.search('\[.+\]',line).group(0).strip('[]').split(':') 
                self.var[ProcessVariable(host, port, kind, addr, size, varname)] = varname

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
            if reason = SRTAG_CLONE:
                if dport == MODBUS_PORT:
                    # Send request to controller 
                    req = Flow(srcip, dstip, trans_id, dport, proto)
                    switch = [identifier]
                    funcode = pkt[Modbus].funcode
                    transId = pkt[Modbus].transId
                    addr = pkt[Modbus].startAddr
                    kind = ProcessVariable.funcode_to_kind(funcode)
                    self.transId[transId] =  ProcessVariable( dstip, dport, kind, addr) 
                    # retrieve kind
                    self.client.mirror(req, switch)
                else: 
                    # Receive request 
                    # Update physical process variable
                    pass
    
        packet.drop()


def main():

    nfqueue = NetfilterQueue()
    handler = PacketHandler(varfile, host, port)
    nfqueue.bind(2, handler.print_and_accept)

    try: 
        nfqueue.run()
    except KeyboardInterrupt:
        print "Done"
    transport.close()
    nfqueue.unbind()

if __name__=='main':
    main()
