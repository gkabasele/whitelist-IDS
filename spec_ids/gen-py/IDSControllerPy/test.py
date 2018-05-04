from utils import *
from stateCompute import *

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


s.var[T1].value = 20
s.var[VT].value = 0
s.var[WC].value = 0
s.var[WE].value = 0
s.var[TF].value = 0
s.var[M1].value = 0
s.var[M2].value = 0
s.var[S2].value = 0

i,d = s.get_req_distance()
print "id: %d, d: %s" % (i,d)

s.var[T1].value = 40
i, d = s.get_req_distance()
print "id: %d, d: %s" % (i,d)


