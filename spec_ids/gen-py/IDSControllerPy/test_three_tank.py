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
logger = logging.getLogger('__name__')

normal = 'three_tank.yml'

state_normal = State(normal)

T3 = "t3"
V1 = "v1"
V2 = "v2"
V3 = "v3"

state_normal.var[T3].value = 0
state_normal.var[V1].value = 0
state_normal.var[V2].value = 0
state_normal.var[V3].value = 0

phase = 1

def change_value(name, value):
    state_normal.var[name].value = value

def display_distance():
    global phase
    print "*********Phase {}**********".format(phase)
    print [(n,x.value) for n,x in state_normal.var.iteritems()]
    identifier_normal, dist_normal = state_normal.get_max_distance()
    identifier_minimal, dist_minimal = state_normal.get_min_distance()
    print "Normal id: {}, d: {}".format(identifier_normal, dist_normal)
    print "Minimal id: {}, d: {}".format(identifier_minimal, dist_minimal)
    print "Diff : {}".format(abs(dist_normal - dist_minimal))
    print "--------------------------"
    logger.warn("Phase: {}".format(phase))
    phase += 1

display_distance()

change_value(V1, 1)
display_distance()

for i in range(0, 25, 5):
    change_value(T3, i)
    display_distance()

change_value(V1, 0)
change_value(V2, 1)
display_distance()

for  i in range(20, 70, 10):
    change_value(T3, i)
    display_distance()

change_value(V2, 0)
change_value(V3, 1)
display_distance()

change_value(T3, 0)
display_distance()
