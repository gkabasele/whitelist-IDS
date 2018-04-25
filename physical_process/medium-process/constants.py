from pyics.utils import *

# Variable Name
A1 = "approvisioning1"
A2 = "approvisioning2"

V1 = "valve1"
V2 = "valve2"
T1 = "tank1"
M1 = "motor1"

VT1 = "valveTank1"

S1 = "silo1"
VS1 = "valveSilo1"

S2 = "silo2"
VS2 = "valveSilo2"
M2 = "motor2"

TC = "tankCharcoal"
VTC = "valveTankCharcoal"

WE = "wagonEnd"
WC = "wagonCar"
WM = "wagonMoving"
WO = "wagonlidOpen"
WS = "wagonStart"

TF = "tankFinal"
VTF = "valveTankFinal"

# Type

varmap = {
        
        A1  : (HR,1),             
        A2  : (HR,1), 
        V1  : (CO,1), 
        V2  : (CO,1), 
        T1  : (HR,1), 
        M1  : (CO,1), 
        VT1 : (CO,1),
        S1  : (HR,1), 
        VS1 : (CO,1),
        S2  : (HR,1),
        VS2 : (CO,1),
        M2  : (CO,1),         
        TC  : (HR,1),
        VTC : (CO,1),
        WE  : (CO,1), 
        WC  : (HR,1), 
        WM  : (CO,1),
        WO  : (CO,1),
        WS  : (CO,1), 
        TF  : (HR,1),
        VTF : (CO,1)
        }

# Store
STORE = './variables'
EXPORT_VAR ='./lplc_var'
PLCS_DIR = './plcs'
TEMPLATES_DIR = 'templates'
PERIOD = 1
DURATION = 75

LOG = "ics.log"
