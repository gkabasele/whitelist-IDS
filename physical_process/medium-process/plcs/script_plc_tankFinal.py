import argparse
import logging
import sys
from pyics.utils import *
from pyics.plc import *
#from constants import *

print "Launching tankFinal"

def main(args):
    plc = PLC(args.ip, args.port, args.store, "plc-tankFinal", tankFinal = ('h', 1))
    if args.create_ex:
        plc.export_variables(args.filename)
    plc.run("tankFinal", args.period, args.duration)
    plc.wait_end(True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", dest="ip", default="localhost", action="store")
    parser.add_argument("--port", dest="port", type=int, action="store")
    parser.add_argument("--store", dest="store", action="store")
    parser.add_argument("--period", dest="period", type=int, default=1, action="store")
    parser.add_argument("--duration", dest="duration", type=int, default=60, action="store")
    parser.add_argument("--export", dest="filename", action="store")
    parser.add_argument("--create", dest="create_ex", action="store_true")
    args, unknown = parser.parse_known_args()
    print(args)
    main(args)