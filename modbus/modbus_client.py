from pymodbus.client.sync import ModbusTcpClient
from pymodbus.client.sync import ConnectionException
import argparse
import time
import sys
import random
import threading 

request = True
value = 1
#Duration in second
MIN = 60
DURATION = MIN*2

class ModbusClientThread (threading.Thread):
    def __init__(self, rate, name, client):
        threading.Thread.__init__(self)
        self.name = name
        self.client = client 
        self.rate = rate
        print "Creating %s" %name

    def run(self):
        normal_operation(self.rate, self.name, self.client)        

def do_every(period, name, number, max_req, rate, f, *args):
    def g_tick():
        t = time.time()
        count = 0
        while True:
            count +=1
            yield max(t + count*period - time.time(),0)
    g = g_tick()
    n_req = 0
    #number = specify if we stop after a certain amount of
    #request or a period of time
    if number:
        while n_req < max_req:
            f(*args)
            n_req+=1
            time.sleep(next(g))
    else:
        start_time = time.time()
        turn = 0
        while True:
            current_time = time.time()
            if (current_time-start_time) >= DURATION:
                break
            for i in xrange(rate):
                f[turn % len(f)](*args)
            print "%s Request:%s"%(name, request)
            turn +=1
            time.sleep(next(g))
        

def write_request(client):
    print "writing coil value"
    client.write_coil(1,not request)

def read_request(client): 
    print "reading coil value"
    result = client.read_coils(1,1)
    global request
    request = result.bits[0]
    if result:
        print result.bits[0]

def write_req_holding(client):
    print "writing holding register value"
    client.write_register(1, value + 1)
    
def read_req_holding(client):
    print "reading holding register value"
    resp = client.read_holding_registers(1,1)
    if resp:
        global value
        value += 1
        print resp.registers[0]


def normal_operation(rate,name, client):
    do_every(2, name, False, 0, rate, [write_request, read_request, write_req_holding, read_req_holding], client) 

parser = argparse.ArgumentParser()
parser.add_argument("--rate", dest="rate", type=int, action="store", default = 1)
parser.add_argument("--ip-master", dest="master_ip", action="store", help="IP address of the master")
parser.add_argument("--port-master", dest="master_port", type=int, action="store", help="port of the master")
parser.add_argument("--ip-slaves",  dest="slaves_ip", action="append")
parser.add_argument("--port-slaves", dest="slaves_port", type=int, action="append")
args = parser.parse_args()

# First field site
c_address = args.master_ip
c_port = args.master_port
rate = args.rate

slaves_ip = args.slaves_ip
slaves_port = args.slaves_port
modbus_clients = []

for i in xrange(len(slaves_ip)):
    addr = slaves_ip[i]
    dport = slaves_port[i]
    try:
        client = ModbusTcpClient(host=addr, port=dport, source_address=(c_address, c_port+i))
        modbus_clients.append(client)
    except ConnectionException:
        print "Unable to connect to Modbus Server %s:%d" % (addr,dport)
        sys.exit()
        

try:
    field_sites = []

    # Creating threads
    for i in xrange(len(modbus_clients)):
        field_site = ModbusClientThread( rate,"fs-%d"%i, modbus_clients[i])
        field_sites.append(field_site)
    
    # Starting threads
    for f in field_sites: 
        f.start()

    # Waiting for an answer
    for f in field_sites:
        f.join()

except:
    print "Error: unable to start thread"
finally:
    for c in modbus_clients:
        c.close()
