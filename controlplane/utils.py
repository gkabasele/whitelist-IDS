from scapy.all import *
import struct
import socket
import cPickle as pickle
import sys

class SRTag(Packet):
    name = "SRTagPacket"
    fields_desc=[ IPField("dst", None),
                  ShortField("identifier", 0),
                  ByteField("protocol", 6),
                  ByteField("reason", 0)
                ]
 
class Modbus(Packet):
    name = "ModbusHeader"
    fields_desc=[ ShortField("transactionID", 0),
                  ShortField("protocolID", 0),
                  ShortField("length", 6),
                  ByteField("unitID", 0),
                  ByteField("funcode", 1)
                ]

class FlowRequest():

    req_id = 0

    def __init__(self, 
                 reason,
                 srcip,
                 sport,
                 dstip,
                 dport,
                 proto,
                 funcode,
                 length):

            self.req_id = FlowRequest.req_id
            FlowRequest.req_id += 1
            self.reason = reason
            self.srcip = srcip
            self.sport = sport
            self.dstip = dstip
            self.dport = dport
            self.proto = proto 
            self.funcode = funcode
            self.length = length

    def __len__(self):
        return sys.getsizeof(self)

class FlowResponse():
    
    def __init__(self, req_id, code):
        self.req_id = req_id
        self.code = code    

    def __len__(self):
        return sys.getsizeof(self)

class Communication():
    @staticmethod
    def recvall(sock, n):
        data = ''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data
    
    @staticmethod
    def recv_msg(sock):
        raw_msglen = Communication.recvall(sock, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return Communication.recvall(sock, msglen)
    
    
    @staticmethod
    def send(data, sock):
        length = len(data)
        if length > 0:
            data = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
            data = struct.pack('>I', len(data)) + data
            sock.sendall(data)
