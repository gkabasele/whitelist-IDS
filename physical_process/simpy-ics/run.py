import os
import time 
import logging
import simpy
import simpy.rt
import subprocess
import threading
import shutil
import argparse

from pyics.component_process import ComponentProcess
from pyics.utils import *
from constants import *


parser = argparse.ArgumentParser()
parser.add_argument("--create", dest="create_dir", action="store_true")
args = parser.parse_args()

if os.path.exists(LOG):
    os.remove(LOG)

logging.basicConfig(filename = LOG, mode = 'w', format='[%(asctime)s][%(levelname)s][%(pathname)s-%(lineno)d] %(message)s', level = logging.DEBUG)

# Three tank system 
class TTankSystem(ComponentProcess):

    def __init__(self, env, store, name, *args, **kwargs):

        super(TTankSystem, self).__init__(env, store, name, *args, **kwargs)

        self.tank1 = 50
        self.tank2 = 50
        self.tank3 = 0
        self.pump1 = False
        self.pump2 = False
        self.valve = False

        self.set(TANK1, self.tank1)
        self.set(TANK2, self.tank2)
        self.set(TANK3, self.tank3)
        self.set(PUMP1, False)
        self.set(PUMP2, False)
        self.set(VALVE, False)

    def computation( self, *args, **kwargs):

        decrease_duration = 3
        
        for i in range(10):
            print "(%d) Starting three tank system" % (self.env.now)
            self.pump1 = self.get(PUMP1, "b")
            if self.pump1:
                print "(%d) Pump1 is open, passing fluid from tank1 to tank3" % (self.env.now)
                yield self.env.timeout(decrease_duration)
                self.tank1 -= 20
                self.set(TANK1, self.tank1)
                self.tank3 += 20
                self.set(TANK3, self.tank3)
                self.pump1 = False
                self.set(PUMP1, self.pump1)
            
            self.pump2 = self.get(PUMP2, "b")
            if self.pump2:
                print "(%d) Pump2 is open, passing fluid from tank2 to tank3" % (self.env.now)
                yield self.env.timeout(decrease_duration)
                self.tank2 -= 20
                self.set(TANK2, self.tank2)
                self.tank3 += 20
                self.set(TANK3, self.tank3)
                self.pump2 = False
                self.set(PUMP2, self.pump2)

            self.valve = self.get(VALVE, "b")
            if self.valve:
                print "(%d) Valve is open, releasing %d of fluid from tank3 " %(self.env.now, self.tank3)
                yield self.env.timeout(2*decrease_duration)
                self.tank3 = 0
                self.set(TANK3, self.tank3)
                self.valve = False
                self.set(VALVE, self.valve)
                
            print "(%d) Approvisionning tank 1 and 2" % (self.env.now)
            yield self.env.timeout(decrease_duration)
            self.tank1 += 20
            self.set(TANK1, self.tank1)
            self.tank2 += 20
            self.set(TANK2, self.tank2)
            

if os.path.exists(STORE):
    shutil.rmtree(STORE)

if args.create_dir:
    if os.path.exists(EXPORT_VAR):
        shutil.rmtree(EXPORT_VAR)
    os.mkdir(EXPORT_VAR)

env = simpy.rt.RealtimeEnvironment(factor=1)
phys_proc = (TTankSystem(env, STORE, "Three Tank System"))

t = threading.Thread(name='process', target=env.run)
t.start()

# run PLC
py = "python"
ip = "localhost"
ip_args = "--ip"
port_args = "--port"
store_args = "--store"
prefix = "script_plc_"
ex = "--export"
dur_args = "--duration"
cre = "--create" if args.create_dir else ""

tank1_proc = subprocess.Popen([py, prefix+"tank1.py", ip_args, ip, port_args, str(5020), store_args, STORE, dur_args, str(DURATION), ex, EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
tank2_proc = subprocess.Popen([py, prefix+"tank2.py", ip_args, ip, port_args, str(5021), store_args, STORE, dur_args, str(DURATION), ex, EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
tank3_proc = subprocess.Popen([py, prefix+"tank3.py", ip_args, ip, port_args, str(5022), store_args, STORE, dur_args, str(DURATION), ex, EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
pump1_proc = subprocess.Popen([py, prefix+"pump1.py", ip_args, ip, port_args, str(5023), store_args, STORE, dur_args, str(DURATION), ex, EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
pump2_proc = subprocess.Popen([py, prefix+"pump2.py", ip_args, ip, port_args, str(5024), store_args, STORE, dur_args, str(DURATION), ex, EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
valve_proc = subprocess.Popen([py, prefix+"valve.py", ip_args, ip, port_args, str(5025), store_args, STORE, dur_args, str(DURATION), ex, EXPORT_VAR, cre], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

mtu_proc = subprocess.Popen([py, "script_mtu.py", ip_args, ip, port_args, str(3000), dur_args, str(DURATION), "--import" ,EXPORT_VAR], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

(tank1_out, tank1_err) = tank1_proc.communicate()
(tank2_out, tank2_err) = tank2_proc.communicate()
(tank3_out, tank3_err) = tank3_proc.communicate()
(pump1_out, pump1_err) = pump1_proc.communicate()
(pump2_out, pump2_err) = pump2_proc.communicate()
(valve_out, valve_err) = valve_proc.communicate()
(mtu_out, mtu_err) = mtu_proc.communicate()

print tank1_out
print tank1_err
print tank2_out
print tank2_err
print tank3_out
print tank3_err
print pump1_out
print pump1_err
print pump2_out
print pump2_err
print valve_out
print valve_err
print mtu_out
print mtu_err


tank1_proc.wait()
pump1_proc.wait()
tank2_proc.wait()
pump2_proc.wait()
tank3_proc.wait()
valve_proc.wait()
mtu_proc.wait()

t.join()
