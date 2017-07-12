# !/usr/bin/env python2

import json

class SwitchConfEncoder(json.JSONEncoder):
    def default(self, obj):
        if not isinstance(obj,SwitchConf):
            return super(SwitchEncoder, self).default(obj)
        return obj.to_json() 

class SwitchCollection():

    def __init__(self):
        self.switches_conf = {}

    def add_switch_conf(self, dpid, switch_conf):
        self.switches_conf[dpid] = switch_conf

    def get_switch_conf(self, dpid):
        return self.switches_conf[dpid]

    def encode_switch_conf(self, filename):
        with open(filename, 'a+') as f:
            f.write("{\n\t\"switches\": ")
            f.write(json.dumps(self.switches_conf.values(),
                               cls=SwitchConfEncoder,
                               indent=8,
                               separators=(',',':')))
            f.write("\n}")

class SwitchConf():

    def __init__(self,
                 dpid = 0,
                 ip_address = "127.0.0.1",
                 real_ip = None, 
                 port = 9090,
                 resp_network = None,
                 interfaces = None,
                 ids_port = None,
                 gw_port = None,
                 routing_table = None,
                 arp_table = None,
                ):
        self.dpid = dpid
        self.ip_address = ip_address
        self.real_ip = real_ip
        self.port = port
        self.ids_port = ids_port
        self.gw_port = gw_port
        self.resp_network = resp_network if resp_network else []
        self.interfaces = interfaces if interfaces else []
        self.routing_table = routing_table if routing_table else []
        self.arp_table = arp_table if arp_table else []
        
        self.current_intf = 1


    def add_interface( self, intf):
        self.interfaces.append(intf)
        self.current_intf += 1


    def to_json(self):
        value = self.__dict__
        value.pop('current_intf',None)
        return value 




