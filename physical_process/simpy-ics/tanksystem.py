from pymodbus.client.sync import ModbusTcpClient
from pyics.mtu import MTU, ProcessRange
from constants import *

class MTUTankSystem(MTU):

    def __init__(self, ip, port, client=ModbusTcpClient):

        self.tank1 = 50
        self.tank2 = 50
        self.tank3 = 0
        self.pump1 = False
        self.pump2 = False
        self.valve = False

        super(MTUTankSystem, self).__init__(ip, port, client)


    def main_loop(self, *args, **kwargs):
        self.tank1 = self.get_variable(TANK1)
        self.tank2 = self.get_variable(TANK2)
        self.tank3 = self.get_variable(TANK3)
        self.pump1 = self.get_variable(PUMP1)
        self.pump2 = self.get_variable(PUMP2)
        self.valve = self.get_variable(VALVE)

        if self.tank3 is not None:
            if self.tank3 >= 0 and self.tank3 < 20:
                self.pump1 = True
                self.write_variable(PUMP1, self.pump1)
            elif self.tank3 >= 20 and self.tank3 < 40:
                self.pump2 = True
                self.write_variable(PUMP2, self.pump2)
            elif self.tank3 >= 40:
                self.valve = True
                self.write_variable(VALVE, self.valve)



