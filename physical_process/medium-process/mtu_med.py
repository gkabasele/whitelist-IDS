import logging
from pymodbus.client.sync import ModbusTcpClient
from pyics.mtu import MTU, ProcessRange
from constants import *


logger = logging.getLogger(__name__)

class MTUMedSystem(MTU):

    def __init__(self, ip, port, client=ModbusTcpClient):

        self.varmap = {
        
                            A1  : 0,             
                            A2  : 0, 
                            V1  : False, 
                            V2  : False, 
                            T1  : 0, 
                            M1  : False, 
                            VT1 : False,
                            S1  : 0, 
                            VS1 : False,
                            S2  : 0,
                            VS2 : False,
                            M2  : False,         
                            TC  : 0,
                            VTC : False,
                            WE  : False, 
                            WC  : 0, 
                            WM  : False,
                            WO  : False,
                            WS  : False, 
                            TF  : 0,
                            VTF : False
        }

        self.running_m1 = False
        self.running_m2 = False

        super(MTUMedSystem, self).__init__(ip, port, client)

    def main_loop(self, *args, **kargs):


        for k,v in self.varmap.iteritems():
            self.varmap[k] = self.get_variable(k)
            
        logger.info("%s" % self.varmap) 

        if any( x is None for x in self.varmap.itervalues()):
           return 
        
        self.tank1_management()
        self.wagon_management()

        if self.varmap[S2] < 20:
            if self.varmap[VS2]:
                self.change_coil(VS2, False)

        elif self.varmap[S2] == 20 :
            if self.varmap[S1] > 0 :
                self.change_coil(VS1, True)
        
        elif self.varmap[S2] == 60 : 
            if self.varmap[S1] == 0:
                self.change_coil(VS1, False)

            if self.varmap[M2]:
                if self.varmap[TF] < 60:
                    self.change_coil(M2, False)
                    self.change_coil(VS2, True)
            else:
                self.change_coil(M2, True)
        
        if self.varmap[TF] < 60:
            if self.varmap[VTF]:
                self.change_coil(VTF,False)
        elif self.varmap[TF] == 60:
            self.change_coil(VTF, True)


    def tank1_management(self):
        if self.varmap[T1] < 40:
            if self.varmap[VT1]:
                self.change_coil(VT1, False)

            if self.varmap[T1] >= 0 and self.varmap[T1] <20:
                self.change_coil(V1, True)
                if self.varmap[V2]:
                    self.change_coil(V2, False)

            if self.varmap[T1] >= 20 :
                self.change_coil(V2, True)
                if self.varmap[V1]:
                    self.change_coil(V1, False)

        elif self.varmap[T1] == 40:
            if self.varmap[V1]:
                self.change_coil(V1, False)
            if self.varmap[V2]:
                self.change_coil(V2, False)                
            
            if self.varmap[M1]: 
                if self.varmap[S1] < 40:
                    self.change_coil(M1, False)
                    self.change_coil(VT1, True)
            else:
                self.change_coil(M1, True)

    def wagon_management(self):
        if self.varmap[WS]:
           if self.varmap[WC] < 20:
               self.change_coil(VTC, True)
           elif self.varmap[WC] == 20:
               self.change_coil(VTC, False)
               self.change_coil(WM, True)
        elif self.varmap[WE]: 
            if self.varmap[WC] == 20 and self.varmap[S2] == 0:
               self.change_coil(WO, True)
            elif self.varmap[WC] < 20:
               self.change_coil(WO, False)
               self.change_coil(WM, True)

                
    def change_coil(self, name, val):
        if self.varmap[name] != val:
            self.varmap[name] = val
            self.write_variable(name, val)
            logger.info("Changing %s to %s" %(name, val)) 


