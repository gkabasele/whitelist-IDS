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
    dist = state_normal.get_max_distance()
    print "Max id: {}, d: {}".format(dist.max_identifier, dist.max_dist)
    print "Min id: {}, d: {}".format(dist.min_identifier, dist.min_dist)
    print "Diff : {}".format(abs(dist.max_identifier - dist.min_identifier))
    print "--------------------------"
    logger.warn("Phase: {}".format(phase))
    phase += 1

display_distance()

change_value(V1, 1)
display_distance()

for i in range(0, 20, 5):
    change_value(T3, i)
    display_distance()

change_value(V1, 0)
change_value(V2, 1)
display_distance()

for  i in range(20, 60, 10):
    change_value(T3, i)
    display_distance()

change_value(V2, 0)
change_value(V3, 1)
display_distance()

change_value(T3, 0)
display_distance()
