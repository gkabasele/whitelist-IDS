import logging
import os
from stateCompute import State

log = 'test.log'
if os.path.exists(log):
    os.remove(log)

logging.basicConfig(level=logging.DEBUG,
                    format ='%(levelname)s %(message)s',
                    filename=log,
                    filemode='w')

critical = 'requirements_test.yml'
normal = 'normal_test.yml'

state_critical = State(critical)
state_normal = State(normal)

T1 = "tank1"
VT = "valvecharcoal"
WC = "wagoncar"
WE = "wagonend"
TF = "tankfinal"
M1 = "motor1"
M2 = "motor2"
S2 = "silo2"

state_normal.var[T1].value = 0
state_normal.var[VT].value = 0
state_normal.var[WC].value = 0
state_normal.var[WE].value = 0
state_normal.var[TF].value = 0
state_normal.var[M1].value = 0
state_normal.var[M2].value = 0
state_normal.var[S2].value = 0

state_critical.var[T1].value = 0
state_critical.var[VT].value = 0
state_critical.var[WC].value = 0
state_critical.var[WE].value = 0
state_critical.var[TF].value = 0
state_critical.var[M1].value = 0
state_critical.var[M2].value = 0
state_critical.var[S2].value = 0
phase = 1

def change_value(name, value):
    state_critical.var[name].value = value
    state_normal.var[name].value = value

def display_distance():
    global phase
    identifier_crit, dist_crit = state_critical.get_min_distance()
    identifier_normal, dist_normal = state_normal.get_max_distance()
    print "*********Phase {}**********".format(phase)
    print "Critical id: {}, d: {}".format(identifier_crit, dist_crit)
    print "Normal id: {}, d: {}".format(identifier_normal, dist_normal)
    print "--------------------------"
    phase += 1
#Phase 1
display_distance()

#Phase 2
change_value(VT, 1)
change_value(T1, 20)

display_distance()

#Phase 3
change_value(VT, 0)
change_value(WC, 20)
change_value(T1, 40)

display_distance()

#Phase 4
change_value(M1, 1)
change_value(WE, 1)

display_distance()

#Phase 5
change_value(M1, 0)
change_value(T1, 0)
change_value(S2, 20)
change_value(WC, 0)

display_distance()

#Phase 6
change_value(S2, 60)
change_value(WE, 0)
change_value(T1, 20)

display_distance()

#Phase 7
change_value(M2, 1)
change_value(VT, 1)
change_value(T1, 40)
display_distance()

#Phase 8
change_value(M2, 0)
change_value(WC, 20)

display_distance()

#Phase 9
change_value(TF, 55)
display_distance()

#Phase 10
change_value(S2, 55)
display_distance()
