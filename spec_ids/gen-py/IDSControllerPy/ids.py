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

args = parser.parse_args()
host = args.host
port = args.port

bind_layers(IP, SRTag, proto=200)
bind_layers(SRtag, TCP, proto=6)
bind_layers(TCP, Modbus, sport=MODBUS_PORT)
bind_layers(TCP, Modbus, dport=MODBUS_PORT)


socket = TSocket.TSocket(host, port)
transport = TTransport.TBufferedTransport(socket)
protocol = TBinaryProtocol.TBinaryProtocol(transport)
client = Controller.Client(protocol)
transport.open()

def print_and_accept(packet):

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
                # send request to controller 
                req = Flow(srcip, dstip, trans_id, dport, proto)
                switch = [identifier]
                client.mirror(req, switch)
            else: 
                # Receive request update
                pass

    packet.drop()


def main():

    nfqueue = NetfilterQueue()
    nfqueue.bind(2, print_and_accept)

    try: 
        nfqueue.run()
    except KeyboardInterrupt:
        print "Done"
    transport.close()
    nfqueue.unbind()

if __name__=='main':
    main()
