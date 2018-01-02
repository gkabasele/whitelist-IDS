from pymodbus.client.sync import ModbusTcpClient
import time
import sys
import random
from threading import Thread

request = False
#Duration in second
MIN = 60
DURATION = MIN*10


def do_every(period,number,max_req,f,*args):
    def g_tick():
        t = time.time()
        count = 0
        while True:
            count +=1
            yield max(t + count*period -time.time(),0)
    g = g_tick()
    n_req = 0
    if number:
        while n_req < max_req:
            f(*args)
            n_req+=1
            time.sleep(next(g))
    else:
        start_time = time.time()
        while True:
            current_time = time.time()
            if (current_time-start_time) >= DURATION:
                break
            f(*args)
            time.sleep(next(g))
        

def request_packet(client):
    global request
    print "sending burst packet"
    client.write_coil(1,request)

def send_receive(client): 
    result = client.read_coils(1,1)
    if result:
        print result.bits[0]

def normal_operation(client):
    do_every(2,False,0,send_receive,client) 

def burst(client):
    interval = 0.05
    nb_request = 5
    time.sleep(5)
    start_time = time.time()
    while True:
        current_time = time.time() 
        if (current_time-start_time) >= DURATION:
            break
        test = random.randint(0,9)
        print "Generate number %d" %test
        if test == 7:
            print "Burst Mode nb: %d, int: %f\n" % (nb_request,interval)
            do_every(interval,True,nb_request,request_packet,client)
            global request
            request = not request
        time.sleep(1)    
        

addr = sys.argv[1]
dport = int(sys.argv[2])
#saddr = sys.argv[3]
#sport = int(sys.argv[4])

client = ModbusTcpClient(host=addr,port=dport)
#client = ModbusTcpClient(host=addr,port=dport,source_address=(saddr,sport))
try:
    normal = Thread(target=normal_operation,args=(client,),name="normal")
    operator = Thread(target=burst,args=(client,),name="operator")
    normal.start()
    operator.start()
    normal.join()
    operator.join()
except:
    print "Error: unable to start thread",sys.exc_info()[0]
finally:
    print "Closing connection"
    client.close()
