from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct  import *

class SRTag(Packet):
    name = "SRTagPacket"
    fields_desc=[ IPField("dst", None),
                  ShortField("identifier", 0),
                  ByteField("protocol", 200),
                  ByteField("reason", 0)
                ]
    


def print_and_accept(packet):
    
    print(packet)
    payload = packet.get_payload()
    (dst, identifier, protocol, reason)  = unpack('ihbb', payload[-8:])
    print dst
    print identifier
    print protocol
    print reason
    #reason =  unpack('tag[-1]
    #identifier = tag[-3:-1]
    #protocol = tag[-4:-3]
    #dest = tag[-8:-4]
    #print hexdump(reason)
    #print hexdump(identifier)
    #print hexdump(protocol)
    #print hexdump(dest)
    
    #print hexdump(tag[-8:])
    #bind_layers(IP, TCP, proto=200)
    #pkt = IP(payload)
    #print len(str(pkt))
    #print "IP header size: ", len(str(pkt[IP]))
    #print "TCP header size: ", len(str(pkt[TCP]))
    #print str(pkt[SRTag].protocol)
    #print str(pkt[SRTag].identifier)
    #print str(pkt[SRTag].reason)
    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print "Done"

nfqueue.unbind()
