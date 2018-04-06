import argparse
import logging
import time
from pyics.utils import *
from pyics.mtu import *
from constants import *
from tanksystem import MTUTankSystem


def main(args):
    time.sleep(1)
    mtu =  MTUTankSystem(args.ip, args.port)
    mtu.get_dir(args.filename)
    mtu.create_task('mtu', args.period, args.duration)
    mtu.start()
    mtu.wait_end()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", dest="ip", default="localhost", action="store")
    parser.add_argument("--port", dest="port", default="port", type=int, action="store")
    parser.add_argument("--period", dest="period", type=int, default=1, action="store")
    parser.add_argument("--duration", dest="duration", type=int, default=60, action="store")
    parser.add_argument("--import", dest="filename", action="store")
    args = parser.parse_args()
    main(args)
