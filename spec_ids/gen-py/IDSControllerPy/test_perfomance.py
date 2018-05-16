import timeit
import os
import re

def is_int(s):
    try:
        return int(s)
    except:
        return s

def alphanum_key(s):
    """ Convert String to a list of string  "z23a" -> ["z", 23, "a"] 
    """
    return [ is_int(c) for c in re.split('([0-9]+)', s) ]

def sort_numeric(l):
    """ alphanumeric and not lexicographic"""
    l.sort(key=alphanum_key)
    return l


def distance_time():
    tests = []

    for filename in sort_numeric(os.listdir("scal_test")):
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

    cur_dir = os.getcwd()
    index = cur_dir.find('spec_ids')
    filename = cur_dir[:index] + "measurements/performance_test.csv"

    with open(filename, 'w') as f:
        f.write("#Number Requirement,Time(s)\n")
        for i in xrange(len(tests)):
            times = timeit.repeat(setup=setup_code,
                                  stmt=tests[i][1],
                                  repeat=3,
                                  number=1)
            num_var = tests[i][0].replace('req_', '').replace('.yml', '')
            f.write('%s,%s\n' % (num_var, sum(times)/len(times)))

if __name__=="__main__":
    distance_time()


