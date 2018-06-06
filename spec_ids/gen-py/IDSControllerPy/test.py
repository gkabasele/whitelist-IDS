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

#critical = 'requirements_test.yml'
normal = 'normal_test.yml'

#state_critical = State(critical)
state_normal = State(normal, 1, 1)

T1 = "t1"
VC = "vc"
WC = "wc"
WE = "we"
TF = "tf"
M1 = "m1"
M2 = "m2"
S2 = "s2"

state_normal.var[T1].value = 0
state_normal.var[VC].value = 0
state_normal.var[WC].value = 0
state_normal.var[WE].value = 0
state_normal.var[TF].value = 0
state_normal.var[M1].value = 0
state_normal.var[M2].value = 0
state_normal.var[S2].value = 0

#state_critical.var[T1].value = 0
#state_critical.var[VC].value = 0
#state_critical.var[WC].value = 0
#state_critical.var[WE].value = 0
#state_critical.var[TF].value = 0
#state_critical.var[M1].value = 0
#state_critical.var[M2].value = 0
#state_critical.var[S2].value = 0
phase = 1

def change_value(name, value):
#    state_critical.var[name].value = value
    state_normal.var[name].value = value

def display_distance():
    global phase
#    identifier_crit, dist_crit = state_critical.get_min_distance()
    print "*********Phase {}**********".format(phase)
    print [(n, x.value) for n, x in state_normal.var.iteritems()]
    dist = state_normal.get_max_distance()
    print "Max id: {}, d: {}".format(dist.max_identifier, dist.max_dist)
    print "Min id: {}, d: {}".format(dist.min_identifier, dist.min_dist)
    print "----------------------------"
    phase += 1

display_distance()

change_value(VC, 1)
for i in range(0, 45, 5):
    change_value(T1, i)
    if i <= 20:
        change_value(WC, i)
    display_distance()

change_value(VC, 0)

display_distance()

change_value(M1, 1)
change_value(WE, 1)

display_distance()

change_value(M1, 0)
for i in range(0, 25, 5):
    change_value(S2, i)
    change_value(WC, 20 - i)
    display_distance()

for i in range(0, 45, 5):
    change_value(S2, 20 + i)
    change_value(T1, 40 - i)
    display_distance()

change_value(WE, 0)
display_distance()

change_value(VC, 1)
for i in range(0, 45, 5):
    change_value(T1, i)
    if i <= 20:
        change_value(WC, i)
    display_distance()

change_value(M2, 1)
change_value(VC, 0)
display_distance()

change_value(M2, 0)
display_distance()
for i in range(0, 65, 5):
    change_value(S2, 60 - i)
    change_value(TF, i)
    display_distance()
