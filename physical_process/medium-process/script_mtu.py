import argparse
import logging
import time 
import os
from pyics.utils import *
from pyics.mtu import *
from constants import *
from mtu_med import MTUMedSystem

if os.path.exists(LOG):
    os.remove(LOG)

logging.basicConfig(filename = LOG, mode = 'w', format='[%(asctime)s][%(levelname)s][%(pathname)s-%(lineno)d] %(message)s', level = logging.INFO)

def main(args):
    time.sleep(5)
    mtu = MTUMedSystem(args.ip, args.port)
    mtu.get_dir(args.filename)
    mtu.create_task('mtu', args.period, args.duration)
    mtu.start()
    mtu.wait_end()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", dest="ip", default="localhost", action="store")
    parser.add_argument("--port", dest="port", default=3000, type=int, action="store")
    parser.add_argument("--period", dest="period", type=float, default=1, action="store")
    parser.add_argument("--duration", dest="duration", type=int, default=60, action="store")
    parser.add_argument("--import", dest="filename", action="store")
    args = parser.parse_args()
    main(args)
