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

class Container():

    def __init__(self, value, step, limit=0):
        self.value = value
        self.step = step
        self.limit = limit

    def transfer(self, other):
        if self.value - self.step >= 0:
            self.value -= self.step
            other.value += self.step

class MediumProcess(ComponentProcess):

    def __init__(self, env, store, name, *args, **kwargs):

        super(MediumProcess, self).__init__(env, store, name, *args, **kwargs)


        # approvisionning
        self.approvisioning1 = Container(50, 5, 500)
        self.approvisioning2 = Container(50, 5, 500)

        # first tank
        self.valve1 = False
        self.valve2 = False
        self.motor1 = False
        self.motor2 = False
        self.tank1 = Container(0, 5, 60)
        self.valveTank1 = False
        
        # first silo
        self.silo1 = Container(0, 5, 60)
        self.valveSilo1 = False

        # second silo
        self.silo2 = Container(0, 5, 80)
        self.motor2 = False
        self.valveSilo2 = False

        # second tank (charcoal)
        self.tankCharcoal = Container(20, 5, 500)
        self.valveTankCharcoal = False

        # wagon
        self.wagonEnd = False
        self.wagonCar = Container(0, 5, 40)
        self.wagonStart = True
        self.wagonlidOpen = False
        self.wagonMoving = False

        # final tank
        self.tankFinal = Container(0, 5, 80)
        self.valveTankFinal = False

        self.set(A1, self.approvisioning1.value)
        self.set(A2, self.approvisioning2.value)
        self.set(V1, self.valve1)
        self.set(V2, self.valve2)
        self.set(T1, self.tank1.value)
        self.set(M1, self.motor1)
        self.set(VT1, self.valveTank1)
        self.set(S1, self.silo1.value)
        self.set(VS1, self.valveSilo1)
        self.set(S2, self.silo2.value)
        self.set(VS2, self.valveSilo2)
        self.set(M2, self.motor2)
        self.set(TC, self.tankCharcoal.value)
        self.set(VTC, self.valveTankCharcoal)
        self.set(WE, self.wagonEnd)
        self.set(WC, self.wagonCar.value)
        self.set(WO, self.wagonlidOpen)
        self.set(WM, self.wagonMoving)
        self.set(WS, self.wagonStart)
        self.set(TF, self.tankFinal.value)
        self.set(VTF, self.valveTankFinal)

    def computation(self, *args, **kwargs):

        print "(%d) Staring physiscal process tank" % (self.env.now)

        while True:
            print "(%d) Approvisionning A1 and A2, tankCharcoal" % (self.env.now)
            yield self.env.timeout(carcoal_dur)
            self.approvisioning1.value += 2*amount_fluid_passing
            self.approvisioning2.value += 2*amount_fluid_passing
            self.tankCharcoal.value += 2*amount_fluid_passing
            self.set(A1, self.approvisioning1.value)
            self.set(A2, self.approvisioning2.value)
            self.set(TC, self.tankCharcoal.value)
            self.valves_effect()

    def valves_effect(self):
        if self.get(V1, "b"): 
            self.approvisioning1.transfer(self.tank1) 
            self.set(T1, self.tank1.value)
        if self.get(V2, "b"):
            self.approvisioning2.transfer(self.tank1)
            self.set(T1, self.tank1.value)

        if self.get(VT1, "b"):
            self.tank1.transfer(self.silo1)
            self.set(T1, self.tank1.value)
            self.set(S1, self.silo1.value)

        if self.get(VS1, "b"):
            self.silo1.transfer(self.silo2)
            self.set(S2, self.silo2.value)
            self.set(S1, self.silo1.value)

        if self.get(VTC, "b"):
            self.tankCharcoal.transfer(self.wagonCar)
            self.set(WC, self.wagonCar.value)

        if self.get(WO, "b"):
            self.wagonCar.transfer(self.silo2)
            self.set(WC, self.wagonCar.value)
            self.set(S2, self.silo2.value)

        if self.get(VS2, "b"):
            self.silo2.transfer(self.tankFinal)
            self.set(TF, self.tankFinal.value)
            self.set(S2, self.silo2.value)

    def move_wagon(self):
        print "(%d) moving the wagon" % (self.env.now)
        #yield self.env.timeout(wagon_moving_dur)
        if self.wagonEnd:
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
        print "(%d) tank final is open, releasing %d of tank final" % (self.env.now, self.tankFinal.value)
        #yield self.env.timeout(flow_dur)
        self.tankFinal.value = 0
        self.set(TF, self.tankFinal.value)

    def pass_fluid(self, amount,attr_from, attr_to):
        print "(%d) %s is open, passing fluid to %s" % (self.env.now, attr_from, attr_to)
        #yield self.env.timeout(flow_dur)
        tmp_from = getattr(self, attr_from)
        tmp_to = getattr(self, attr_to)
        tmp_from.transfer(tmp_to)
        #setattr(self, attr_to, Container(tmp_to+increment, tmp_to + (max(0, min(tmp_from, amount)))))
        #setattr(self, attr_from, Container(tmp_from-increment, tmp_from - min(tmp_from, amount)))
        self.set(attr_from, getattr(self, attr_from).value)
        self.set(attr_to, getattr(self, attr_to).value)

    def empty_wagon(self, amount, attr, increment=5):
        print "(%d) [Error] emptying %s"  % (self.env.now, attr)
        tmp = getattr(self, attr)
        tmp.value += tmp.value - increment
        #setattr(self, attr, Container(tmp+increment, tmp - min(tmp, amount)))
        self.set(attr, getattr(self, attr).value)

def start(store, nb_round):
    env = simpy.rt.RealtimeEnvironment(factor=1)
    phys_proc = (MediumProcess(env, store, "Medium Process", nb_round))
    env.run()
