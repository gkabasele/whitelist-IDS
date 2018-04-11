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
        
        for i in range(15):
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


def start(store):
    env = simpy.rt.RealtimeEnvironment(factor=1)
    phys_proc = (TTankSystem(env, store, "Three Tank System"))
    env.run()
