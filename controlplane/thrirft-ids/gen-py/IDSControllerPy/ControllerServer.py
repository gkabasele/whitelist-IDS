from Controller import Iface, Processor
from ttypes import *
from constants import *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

import logging 

logging.basicConfig(level=logging.DEBUG)

class ControllerHandler(Iface):

    def __init__(self):
        pass

    def mirror(self, req, sw):
        if req == None:
            err = IDSControllerControllerException(1, "req is None")
            raise err
        else:
            print req
    
    def redirect(self, req, sw):
        print req

    def block(self, req, sw):
        print req

    def allow(self, req, sw):
        print req

handler = ControllerHandler()
processor = Processor(handler)
transport = TSocket.TServerSocket(port=9090)
tfactory = TTransport.TBufferedTransportFactory()
pfactory = TBinaryProtocol.TBinaryProtocolFactory()

server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
server.serve()

