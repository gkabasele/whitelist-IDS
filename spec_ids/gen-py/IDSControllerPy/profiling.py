import cProfile

from stateCompute import State

path = 'scal_test/req_50.yml'

s = State(path)

cProfile.run('s = State(path)')
#T1 = "tank1"
#VT = "valvecharcoal"
#WC = "wagoncar"
#WE = "wagonend"
#TF = "tankfinal"
#M1 = "motor1"
#M2 = "motor2"
#S2 = "silo2"
#
#s.var[T1].value = 20
#s.var[VT].value = 0
#s.var[WC].value = 0
#s.var[WE].value = 0
#s.var[TF].value = 0
#s.var[M1].value = 0
#s.var[M2].value = 0
#s.var[S2].value = 0
#
#cProfile.run('s.get_req_distance()')
