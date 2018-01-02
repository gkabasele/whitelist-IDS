from pymodbus.server.sync import ModbusTcpServer 
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.diag_message import ForceListenOnlyModeRequest

from pymodbus.transaction import ModbusRtuFramer
import sys
import argparse

from netfilterqueue import NetfilterQueue
from scapy.all import *
from struct import *
import threading

DROP_PKT = False

class Modbus(Packet):
    name = "Modbus"
    fields_desc=[ ShortField("transactionID",0),
                  ShortField("protocolID", 0),
                  ShortField("length", None),
                  ByteField("unitID", 0),
                  ByteField("funcode", None)
                ]

class ModbusDiag(Packet):
    name = "ModbusDiag"
    fields_desc =[ ShortField("subfuncode", None)]

bind_layers(TCP, Modbus, sport=5020)
bind_layers(TCP, Modbus, dport=5020)
bind_layers(Modbus, ModbusDiag, funcode=8)

class FLMThread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self.server = server

    def run(self):
        get_packet(self.server) 

def stop_server(server):            
    def cb(packet):
        

        payload = packet.get_payload()
        pkt = IP(payload)
        if TCP in pkt and (pkt[TCP].sport == 5020 or pkt[TCP].dport == 5020):
            global  DROP_PKT 
            if pkt[ModbusDiag].subfuncode == 4:
                print "Receive Force Listen Mode"
                DROP_PKT = True
            elif pkt[ModbusDiag].subfuncode == 1:
                print "Receive Restart Communication Options"
                DROP_PKT = False
        if DROP_PKT:
            packet.drop()
        else:
            packet.accept()
            
    return cb 
def get_packet(server):
    nfqueue = NetfilterQueue()
    nfqueue.bind(1,stop_server(server))
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print "Done"
    nfqueue.unbind()
    #sniff(iface="eth0", prn=stop_server(server), filter= "tcp port 5020", store=0)

#Data store init
store = ModbusSlaveContext(
   di = ModbusSequentialDataBlock(0, [0]*100),
   co = ModbusSequentialDataBlock(0, [0]*100),
   hr = ModbusSequentialDataBlock(0, [0]*100),
   ir = ModbusSequentialDataBlock(0, [0]*100))
context = ModbusServerContext(slaves=store, single=True)

#server identity
identity = ModbusDeviceIdentification()
identity.VendorName = 'MockPLCs'
identity.ProductCode = 'MP'
identity.VendorUrl = 'http://github.com/bashwork/pymodbus/'
identity.ProductName = 'MockPLC 3000 '
identity.ModelName = 'MockPLC Ultimate'
identity.MajorMinorRevision = '1.0'

parser = argparse.ArgumentParser()
parser.add_argument("--ip", dest="ip_addr", action="store", help="IP address of Modbus Server")
parser.add_argument("--port", dest="port", type=int, action="store", help="port of Modbus Server")
parser.add_argument("--f", dest="flm",default=None, action="store", help="enable support of Force Listen Mode")
args = parser.parse_args()

addr = args.ip_addr
port = args.port
flm = args.flm
#StartTcpServer(context, identity=identity, address=(addr,port))
server = ModbusTcpServer(context,idenetity=identity, address=(addr,port))
# Create Thread
if flm:
    thread1 = FLMThread(server)
    thread1.start()
server.serve_forever()
if flm:
    thread1.join()
