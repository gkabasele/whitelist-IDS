import struct
import sys
from scapy.all import *

# PORT
MODBUS_PORT = 5020

# TAG
SRTAG_REDIRECT = 0
SRTAG_CLONE = 1

class SRTag(Packet):
    name = "SRTag"
    fields_desc = [ IPField("dst", None),
                    ShortField("identifier", None),
                    ByteField("protocol", None),
                    ByteField("reason", None)
                  ]

class Modbus(Packet):
    name = "Modbus"
    fields_desc = [ ShortField("transId", 0),
                    ShortField("protoID", 0),
                    ShortField("length", None),
                    ByteField("unitID", 0),
                    ByteField("funcode", None)
                  ]
