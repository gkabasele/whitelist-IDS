import os
import time
import simpy
import simpy.rt
import subprocess
import threading
import shutil
import argparse

from pyics.component_process import ComponentProcess
from pyics.utils import *
from constants import *

class MediumProcess(ComponentProcess):

    def __init__(self, env, store, name, *args, **kwargs):

        super(MediumProcess, self).__init__(env, store, name, *args, **kwargs)


        # approvisionning
        self.approvisioning1 = 50
        self.approvisioning2 = 50

        # first tank
        self.valve1 = False
        self.valve2 = False
        self.motor1 = False
        self.motor2 = False
        self.tank1 = 0
        self.valveTank1 = False
        
        # first silo
        self.silo1 = 0
        self.valveSilo1 = False

        # second silo
        self.silo2 = 0
        self.motor2 = False
        self.valveSilo2 = False

        # second tank (charcoal)
        self.tankCharcoal = 20
        self.valveTankCharcoal = False

        # wagon
        self.wagonEnd = False
        self.wagonCar = 0
        self.wagonStart = True
        self.wagonlidOpen = False
        self.wagonMoving = False

        # final tank
        self.tankFinal = 0
        self.valveTankFinal = False

        self.set(A1, self.approvisioning1)
        self.set(A2, self.approvisioning2)
        self.set(V1, self.valve1)
        self.set(V2, self.valve2)
        self.set(T1, self.tank1)
        self.set(M1, self.motor1)
        self.set(VT1, self.valveTank1)
        self.set(S1, self.silo1)
        self.set(VS1, self.valveSilo1)
        self.set(S2, self.silo2)
        self.set(VS2, self.valveSilo2)
        self.set(M2, self.motor2)
        self.set(TC, self.tankCharcoal)
        self.set(VTC, self.valveTankCharcoal)
        self.set(WE, self.wagonEnd)
        self.set(WC, self.wagonCar)
        self.set(WO, self.wagonlidOpen)
        self.set(WM, self.wagonMoving)
        self.set(WS, self.wagonStart)
        self.set(TF, self.tankFinal)
        self.set(VTF, self.valveTankFinal)

    def computation(self, *args, **kwargs):

        print "(%d) Staring physiscal process tank" % (self.env.now)

        while True:
            print "(%d) Approvisionning A1 and A2, tankCharcoal" % (self.env.now)
            yield self.env.timeout(carcoal_dur)
            self.approvisioning1 += 2*amount_fluid_passing
            self.approvisioning2 += 2*amount_fluid_passing
            self.tankCharcoal += 2*amount_fluid_passing
            self.set(A1, self.approvisioning1)
            self.set(A2, self.approvisioning2)
            self.set(TC, self.tankCharcoal)

    def move_wagon(self):
        print "(%d) moving the wagon" % (self.env.now)
        #yield self.env.timeout(wagon_moving_dur)
        if self.wagonEnd and self.wagonStart:
            print "[Error] wagon on two positions"
        elif self.wagonEnd:
            self.wagonEnd = False
            self.wagonStart = True
            self.wagonMoving = False
        elif self.wagonStart:
            self.wagonStart = False
            self.wagonEnd = True
            self.wagonMoving = False
        self.set(WE, self.wagonEnd)
        self.set(WS, self.wagonStart)
        self.set(WM, self.wagonMoving)

    def running_motor(self, name):
        print "(%d) running motor %s" % (self.env.now, name)
        #yield self.env.timeout(motor_dur)

    def release_tank(self):
        print "(%d) tank final is open, releasing %d of tank final" % (self.env.now, self.tankFinal)
        #yield self.env.timeout(flow_dur)
        self.tankFinal = 0
        self.set(TF, self.tankFinal)

    def pass_fluid(self, amount,attr_from, attr_to):
        print "(%d) %s is open, passing fluid to %s" % (self.env.now, attr_from, attr_to)
        #yield self.env.timeout(flow_dur)
        tmp_from = getattr(self, attr_from)
        tmp_to = getattr(self, attr_to)
        setattr(self, attr_to, tmp_to + (max(0, min(tmp_from, amount))))
        setattr(self, attr_from, tmp_from - min(tmp_from, amount))
        self.set(attr_from, getattr(self, attr_from))
        self.set(attr_to, getattr(self, attr_to))

    def empty_wagon(self, amount, attr):
        print "(%d) [Error] emptying %s"  % (self.env.now, attr)
        tmp = getattr(self, attr)
        setattr(self, attr, tmp - min(tmp, amount)) 
        self.set(attr, getattr(self, attr))

def start(store, nb_round):
    env = simpy.rt.RealtimeEnvironment(factor=1)
    phys_proc = (MediumProcess(env, store, "Medium Process", nb_round))
    env.run()
