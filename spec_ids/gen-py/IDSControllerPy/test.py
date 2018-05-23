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

path = 'requirements_test.yml'

s = State(path)

T1 = "tank1"
VT = "valvecharcoal"
WC = "wagoncar"
WE = "wagonend"
TF = "tankfinal"
M1 = "motor1"
M2 = "motor2"
S2 = "silo2"

s.var[T1].value = 0
s.var[VT].value = 0
s.var[WC].value = 0
s.var[WE].value = 0
s.var[TF].value = 0
s.var[M1].value = 0
s.var[M2].value = 0
s.var[S2].value = 0

i, d = s.get_min_distance()
a, e = s.get_max_distance()
print "id: {}, d: {}".format(i, d)
print "id: {}, d: {}".format(a, e)
print "--------------------------"
s.var[VT].value = 1
s.var[T1].value = 20

i, d = s.get_min_distance()
a, e = s.get_max_distance()
print "id: {}, d: {}".format(i, d)
print "id: {}, d: {}".format(a, e)
print "--------------------------"
s.var[VT].value = 0
s.var[WC].value = 20
s.var[T1].value = 40

i, d = s.get_min_distance()
a, e = s.get_max_distance()
print "id: {}, d: {}".format(i, d)
print "id: {}, d: {}".format(a, e)
print "--------------------------"
s.var[M1].value = 1
s.var[WE].value = 1

i, d = s.get_min_distance()
a, e = s.get_max_distance()
print "id: {}, d: {}".format(i, d)
print "id: {}, d: {}".format(a, e)
print "--------------------------"

s.var[M1].value = 0
s.var[WE].value = 0
s.var[S2].value = 20
s.var[WC].value = 0

i, d = s.get_min_distance()
a, e = s.get_max_distance()
print "id: {}, d: {}".format(i, d)
print "id: {}, d: {}".format(a, e)
print "--------------------------"
