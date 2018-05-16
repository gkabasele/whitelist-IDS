import timeit
import os

def distance_time():
    tests = []

    for filename in os.listdir("scal_test"):
        if filename.endswith(".yml"):
            test = '''
s = State('scal_test/%s')

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

s.get_req_distance()
            ''' % (filename)
            tests.append((filename, test))
    setup_code = '''
from stateCompute import State
                '''

    for i in xrange(len(tests)):
        times = timeit.repeat(setup=setup_code,
                              stmt=tests[i][1],
                              repeat=3,
                              number=1)
        print 'File : %s, Time : %s' % (tests[i][0], min(times))

if __name__=="__main__":
    distance_time()


