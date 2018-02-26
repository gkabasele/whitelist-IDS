import struct
import sys
from scapy.all import *

# PORT
MODBUS_PORT = 5020

# TAG
SRTAG_REDIRECT = 0
SRTAG_CLONE = 1

# Variable Type

DIS_COIL = "co"
DIS_INP = "di"
HOL_REG = "hr"
INP_REG = "ir"

class ProcessVariable():

    def __init__(self, host, port, kind, addr, size=None, name=None):
        self.host = host
        self.port = port
        self.kind = kind
        self.addr = addr
        self.name = name
        self.size = size
        self.value = None

    @classmethod
    def funcode_to_kind(cls, funcode):
        if funcode in [1, 5, 15]:
            return DIS_COIL
        elif funcode == 2:
            return DIS_INP
        elif funcode in [3,6,10,22,23]:
            return HOL_REG
        elif funcoe == 4:
            return INP_REG
        

    def __eq__(self, other):
        return ((self.host, self.port, self.kind, self.addr) ==
                (other.host, other.port, other.kind, other.addr))

    def __hash__(self):
        return hash(self.host, self.port, self.kind, self.addr)

class SRTag(Packet):
    name = "SRTag"
    fields_desc = [ IPField("dst", None),
                    ShortField("identifier", None),
                    ByteField("protocol", None),
                    ByteField("reason", None)
                  ]

class ModbusReq(Packet):
    name = "ModbusReq"
    fields_desc = [ ShortField("transId", 0),
                    ShortField("protoID", 0),
                    ShortField("length", None),
                    ByteField("unitID", 0),
                    ByteField("funcode", None),
                    ShortField("startAddr", 0)
                  ]
bind_layers(TCP, ModbusReq, dport=MODBUS_PORT)

class ModbusRes(Packet):
    name = "ModbusRes"
    fields_desc = [ ShortField("transId", 0),
                    ShortField("protoID", 0),
                    ShortField("length", None),
                    ByteField("unitID", 0),
                    ByteField("funcode", None)
                  ]
bind_layers(TCP, ModbusRes, sport=MODBUS_PORT)

class ReadCoilsRes(Packet):
    name = "ReadCoilsRes"
    fields_desc = [ FieldLenField("count", None, length_of="status"),
                    ByteField("status", None, length_from=lambda x:x.length)
                  ]
bind_layers(ModbusRes, ReadCoilsRes, funcode=1)

class ReadDiscreteRes(Packet):
    name = "ReadDiscreteRes"
    fields_desc = [ FieldLenField("count", None, length_of="status"),
                   ByteField("status", None, length_from=lambda x:x.length)
                  ]
bind_layers(ModbusRes, ReadDiscreteRes, funcode=2)

class ReadHoldRegRes(Packet):
    name = "ReadHoldRegRes"
    fields_desc = [ FieldLenField("count", None, length_of="value"),
                    ByteField("value", None , length_from=lambda x: 2*x.length)
                  ]
bind_layers(ModbusRes, ReadHoldRegRes, funcode=3)

class ReadInputRes(Packet):
    name = "ReadInputRes"
    fields_desc = [ FieldLenField("count", None , length_of="registers"),
                    ByteField("registers", None, length_from=lambda x: 2*x.length)
                  ]
bind_layers(ModbusRes, ReadInputRes, funcode=4)

class WriteSingleCoilRes(Packet):
    name = "WriteSingleCoilRes"
    fields_desc = [ ShortField("addr",None),
                    ShortField("value",None)
                  ]
bind_layers(ModbusRes, WriteSingleCoilRes, funcode=5)

class WriteSingleRegRes(Packet):
    name = "WriteSingleRegRes"
    fields_desc = [ ShortField("addr", None),
                    ShortField("value", None)
                  ]
bind_layers(ModbusRes, WriteSingleRegRess, funcode=6)

