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

    def __init__(self, env, store, name, nb_round,*args, **kwargs):

        super(MediumProcess, self).__init__(env, store, name, *args, **kwargs)

        self.nb_round = nb_round

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

    def pass_fluid(self, amount,attr_from, attr_to):
        print "(%d) %s is open, passing fluid to %s" % (self.env.now, attr_from, attr_to)
        tmp_from = getattr(self, attr_from)
        tmp_to = getattr(self, attr_to)
        setattr(self, attr_to, tmp_to + (max(0, min(tmp_from, amount))))
        setattr(self, attr_from, tmp_from - min(tmp_from, amount))
        self.set(attr_from, getattr(self, attr_from))
        self.set(attr_to, getattr(self, attr_to))

    def computation(self, *args, **kwargs):

        motor_dur = 3
        flow_dur = 3
        carcoal_dur = 4
        carcoal_push_dur = 2
        wagon_moving_dur = 2

        amount_fluid_passing = 20

        print "(%d) Staring physiscal process tank" % (self.env.now)

        for i in range(self.nb_round):
            self.valve1 = self.get(V1, "b")
            if self.valve1:
                self.pass_fluid(amount_fluid_passing, A1, T1)
                yield self.env.timeout(flow_dur)
                #Close the valve automatically

            self.valve2 = self.get(V2, "b")
            if self.valve2:
               self.pass_fluid(amount_fluid_passing, A2, T1)
               yield self.env.timeout(flow_dur)

            self.motor1 = self.get(M1, "b")
            if self.motor1:
                print "(%d) running motor1" % (self.env.now)
                yield self.env.timeout(motor_dur)

            self.valveTank1 = self.get(VT1, "b")
            if self.valveTank1:
                self.pass_fluid(self.tank1, T1, S1)
                yield self.env.timeout(flow_dur)

            self.valveSilo1 = self.get(VS1, "b")
            if self.valveSilo1:
                self.pass_fluid(self.silo1, S1, S2)
                yield self.env.timeout(flow_dur)

            self.valveTankCharcoal = self.get(VTC, "b")
            self.wagonStart = self.get(WS, "b")
            if self.valveTankCharcoal and self.wagonStart:
                self.pass_fluid(amount_fluid_passing, TC, WC)
                yield self.env.timeout(flow_dur)

            self.wagonMoving = self.get(WM, "b")
            if self.wagonMoving:
                print "(%d) moving the wagon" % (self.env.now)
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

            self.wagonlidOpen = self.get(WO, "b")
            self.wagonEnd = self.get(WE, "b")
            if self.wagonlidOpen  and self.wagonEnd : 
                self.pass_fluid(amount_fluid_passing, WC, S2) 
                yield self.env.timeout(flow_dur)

            self.motor2 = self.get(M2, "b")
            if self.motor2:
                print "(%d) running motor2" % (self.env.now)
                yield  self.env.timeout(motor_dur)

            self.valveSilo2 = self.get(VS2, "b")
            if self.valveSilo2 :
                self.pass_fluid(self.silo2, S2, TF)
                yield self.env.timeout(flow_dur)

            self.valveTankFinal = self.get(VTF, "b")
            if self.valveTankFinal :
                print "(%d) tank final is open, releasing %d of tank final" % (self.env.now, self.tankFinal)
                self.tankFinal = 0
                self.set(TF, self.tankFinal)

            print "(%d) Approvisionning A1 and A2, tankCharcoal" % (self.env.now)
            yield self.env.timeout(carcoal_dur)
            self.approvisioning1 += 2*amount_fluid_passing
            self.approvisioning2 += 2*amount_fluid_passing
            self.tankCharcoal += 2*amount_fluid_passing
            self.set(A1, self.approvisioning1)
            self.set(A2, self.approvisioning2)
            self.set(TC, self.tankCharcoal)

def start(store, nb_round):
    env = simpy.rt.RealtimeEnvironment(factor=1)
    phys_proc = (MediumProcess(env, store, "Medium Process", nb_round))
    env.run()
