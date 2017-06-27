import os
import sys
import struct
import json
import inspect
from netaddr import IPNetwork
from netaddr import IPAddress
from scapy.all import *

import argparse

from functools import wraps
import  bmpy_utils as utils

from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *
try:
    from bm_runtime.simple_pre import SimplePre
except:
    pass
try:
    from bm_runtime.simple_pre_lag import SimplePreLAG
except:
    pass

class ModbusHeader(Packet):
    name="ModbusHeader"
    fields_desc=[
        ShortField("transactionID",0),
        ShortField("protocolID",0),
        ShortField("length",6),
        ByteField("unitID",0),
        ByteField("funcode",1)
    ]

bind_layers(TCP, ModbusHeader, dport=5020)
bind_layers(TCP, ModbusHeader, sport=5020)

# Table name
SEND_FRAME = 'send_frame'
FORWARD = 'forward'
IPV4_LPM = 'ipv4_lpm'
FLOW_ID = 'flow_id'
MODBUS = 'modbus'
EX_PORT = 'ex_port'
MISS_TAG= 'miss_tag_table'
ARP_RESP = 'arp_response'
ARP_FORW = 'arp_forward'

# Action name
DROP = '_drop'
NO_OP = '_no_op'
ADD_TAG = 'add_miss_tag'
REWRITE = 'rewrite_mac'
DMAC = 'set_dmac'
NHOP = 'set_nhop'
ADD_PORT = 'add_expected_port'
REDIRECT = 'redirect_packet'
RESP = 'respond_arp'

# TAG MISS
IP_MISS = '10'
PORT_MISS = '20'
FUN_MISS = '30'

def enum(type_name, *sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())

    @staticmethod
    def to_str(x):
        return reverse[x]
    enums['to_str'] = to_str

    @staticmethod
    def from_str(x):
        return enums[x]

    enums['from_str'] = from_str
    return type(type_name, (), enums)

PreType = enum('PreType', 'None', 'SimplePre', 'SimplePreLAG')
MeterType = enum('MeterType', 'packets', 'bytes')
TableType = enum('TableType', 'simple', 'indirect', 'indirect_ws')


def bytes_to_string(byte_array):
    form = 'B' * len(byte_array)
    return struct.pack(form, *byte_array)

def table_error_name(x):
    return TableOperationErrorCode._VALUES_TO_NAMES[x]

def get_parser():

    class ActionToPreType(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            if nargs is not None:
                raise ValueError("nargs not allowed")
            super(ActionToPreType, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            assert(type(values) is str)
            setattr(namespace, self.dest, PreType.from_str(values))

    parser = argparse.ArgumentParser(description='BM runtime CLI')
    # One port == one device !!!! This is not a multidevice CLI
    parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                        type=int, action="store", default=9090)

    parser.add_argument('--thrift-ip', help='Thrift IP address for table updates',
                        type=str, action="store", default='localhost')

    parser.add_argument('--json', help='JSON description of P4 program',
                        type=str, action="store", required=False)

    parser.add_argument('--pre', help='Packet Replication Engine used by target',
                        type=str, choices=['None', 'SimplePre', 'SimplePreLAG'],
                        default=PreType.SimplePre, action=ActionToPreType)

    return parser

TABLES = {}
ACTION_PROFS = {}
ACTIONS = {}
METER_ARRAYS = {}
COUNTER_ARRAYS = {}
REGISTER_ARRAYS = {}
CUSTOM_CRC_CALCS = {}

class MatchType:
    EXACT = 0
    LPM = 1
    TERNARY = 2
    VALID = 3
    RANGE = 4

    @staticmethod
    def to_str(x):
        return {0: "exact", 1: "lpm", 2: "ternary", 3: "valid", 4: "range"}[x]

    @staticmethod
    def from_str(x):
        return {"exact": 0, "lpm": 1, "ternary": 2, "valid": 3, "range": 4}[x]

class Table:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.match_type_ = None
        self.actions = {}
        self.key = []
        self.default_action = None
        self.type_ = None
        self.support_timeout = False
        self.action_prof = None

        TABLES[name] = self

    def num_key_fields(self):
        return len(self.key)

    def key_str(self):
        return ",\t".join([name + "(" + MatchType.to_str(t) + ", " + str(bw) + ")" for name, t, bw in self.key])

    def table_str(self):
        ap_str = "implementation={}".format(
            "None" if not self.action_prof else self.action_prof.name)
        return "{0:30} [{1}, mk={2}]".format(self.name, ap_str, self.key_str())

class ActionProf:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.with_selection = False
        self.actions = {}
        self.ref_cnt = 0

        ACTION_PROFS[name] = self

    def action_prof_str(self):
        return "{0:30} [{1}]".format(self.name, self.with_selection)

class Action:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.runtime_data = []

        ACTIONS[name] = self

    def num_params(self):
        return len(self.runtime_data)

    def runtime_data_str(self):
        return ",\t".join([name + "(" + str(bw) + ")" for name, bw in self.runtime_data])

    def action_str(self):
        return "{0:30} [{1}]".format(self.name, self.runtime_data_str())

class MeterArray:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.type_ = None
        self.is_direct = None
        self.size = None
        self.binding = None
        self.rate_count = None

        METER_ARRAYS[name] = self

    def meter_str(self):
        return "{0:30} [{1}, {2}]".format(self.name, self.size,
                                          MeterType.to_str(self.type_))

class CounterArray:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.is_direct = None
        self.size = None
        self.binding = None

        COUNTER_ARRAYS[name] = self

    def counter_str(self):
        return "{0:30} [{1}]".format(self.name, self.size)

class RegisterArray:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.width = None
        self.size = None

        REGISTER_ARRAYS[name] = self

    def register_str(self):
        return "{0:30} [{1}]".format(self.name, self.size)

def reset_config():
    TABLES.clear()
    ACTION_PROFS.clear()
    ACTIONS.clear()
    METER_ARRAYS.clear()
    COUNTER_ARRAYS.clear()
    REGISTER_ARRAYS.clear()
    CUSTOM_CRC_CALCS.clear()

def load_json_str(json_str):
    def get_header_type(header_name, j_headers):
        for h in j_headers:
            if h["name"] == header_name:
                return h["header_type"]
        assert(0)

    def get_field_bitwidth(header_type, field_name, j_header_types):
        for h in j_header_types:
            if h["name"] != header_type: continue
            for t in h["fields"]:
                # t can have a third element (field signedness)
                f, bw = t[0], t[1]
                if f == field_name:
                    return bw
        assert(0)

    reset_config()
    json_ = json.loads(json_str)

    def get_json_key(key):
        return json_.get(key, [])

    for j_action in get_json_key("actions"):
        action = Action(j_action["name"], j_action["id"])
        for j_param in j_action["runtime_data"]:
            action.runtime_data += [(j_param["name"], j_param["bitwidth"])]

    for j_pipeline in get_json_key("pipelines"):
        if "action_profiles" in j_pipeline:  # new JSON format
            for j_aprof in j_pipeline["action_profiles"]:
                action_prof = ActionProf(j_aprof["name"], j_aprof["id"])
                action_prof.with_selection = "selector" in j_aprof

        for j_table in j_pipeline["tables"]:
            table = Table(j_table["name"], j_table["id"])
            table.match_type = MatchType.from_str(j_table["match_type"])
            table.type_ = TableType.from_str(j_table["type"])
            table.support_timeout = j_table["support_timeout"]
            for action in j_table["actions"]:
                table.actions[action] = ACTIONS[action]

            if table.type_ in {TableType.indirect, TableType.indirect_ws}:
                if "action_profile" in j_table:
                    action_prof = ACTION_PROFS[j_table["action_profile"]]
                else:  # for backward compatibility
                    assert("act_prof_name" in j_table)
                    action_prof = ActionProf(j_table["act_prof_name"],
                                             table.id_)
                    action_prof.with_selection = "selector" in j_table
                action_prof.actions.update(table.actions)
                action_prof.ref_cnt += 1
                table.action_prof = action_prof

            for j_key in j_table["key"]:
                target = j_key["target"]
                match_type = MatchType.from_str(j_key["match_type"])
                if match_type == MatchType.VALID:
                    field_name = target + "_valid"
                    bitwidth = 1
                elif target[1] == "$valid$":
                    field_name = target[0] + "_valid"
                    bitwidth = 1
                else:
                    field_name = ".".join(target)
                    header_type = get_header_type(target[0],
                                                  json_["headers"])
                    bitwidth = get_field_bitwidth(header_type, target[1],
                                                  json_["header_types"])
                table.key += [(field_name, match_type, bitwidth)]

    for j_meter in get_json_key("meter_arrays"):
        meter_array = MeterArray(j_meter["name"], j_meter["id"])
        if "is_direct" in j_meter and j_meter["is_direct"]:
            meter_array.is_direct = True
            meter_array.binding = j_meter["binding"]
        else:
            meter_array.is_direct = False
            meter_array.size = j_meter["size"]
        meter_array.type_ = MeterType.from_str(j_meter["type"])
        meter_array.rate_count = j_meter["rate_count"]

    for j_counter in get_json_key("counter_arrays"):
        counter_array = CounterArray(j_counter["name"], j_counter["id"])
        counter_array.is_direct = j_counter["is_direct"]
        if counter_array.is_direct:
            counter_array.binding = j_counter["binding"]
        else:
            counter_array.size = j_counter["size"]

    for j_register in get_json_key("register_arrays"):
        register_array = RegisterArray(j_register["name"], j_register["id"])
        register_array.size = j_register["size"]
        register_array.width = j_register["bitwidth"]

    for j_calc in get_json_key("calculations"):
        calc_name = j_calc["name"]
        if j_calc["algo"] == "crc16_custom":
            CUSTOM_CRC_CALCS[calc_name] = 16
        elif j_calc["algo"] == "crc32_custom":
            CUSTOM_CRC_CALCS[calc_name] = 32

class UIn_Error(Exception):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info

class UIn_ResourceError(UIn_Error):
    def __init__(self, res_type, name):
        self.res_type = res_type
        self.name = name

    def __str__(self):
        return "Invalid %s name (%s)" % (self.res_type, self.name)

class UIn_MatchKeyError(UIn_Error):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info

class UIn_RuntimeDataError(UIn_Error):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info

class CLI_FormatExploreError(Exception):
    def __init__(self):
        pass

class UIn_BadParamError(UIn_Error):
    def __init__(self, info=""):
        self.info = info

    def __str__(self):
        return self.info

class UIn_BadIPv4Error(UIn_Error):
    def __init__(self):
        pass

class UIn_BadIPv6Error(UIn_Error):
    def __init__(self):
        pass

class UIn_BadMacError(UIn_Error):
    def __init__(self):
        pass

def ipv4Addr_to_bytes(addr):
    if not '.' in addr:
        raise CLI_FormatExploreError()
    s = addr.split('.')
    if len(s) != 4:
        raise UIn_BadIPv4Error()
    try:
        return [int(b) for b in s]
    except:
        raise UIn_BadIPv4Error()

def macAddr_to_bytes(addr):
    if not ':' in addr:
        raise CLI_FormatExploreError()
    s = addr.split(':')
    if len(s) != 6:
        raise UIn_BadMacError()
    try:
        return [int(b, 16) for b in s]
    except:
        raise UIn_BadMacError()

def ipv6Addr_to_bytes(addr):
    from ipaddr import IPv6Address
    if not ':' in addr:
        raise CLI_FormatExploreError()
    try:
        ip = IPv6Address(addr)
    except:
        raise UIn_BadIPv6Error()
    try:
        return [ord(b) for b in ip.packed]
    except:
        raise UIn_BadIPv6Error()

def int_to_bytes(i, num):
    byte_array = []
    while i > 0:
        byte_array.append(i % 256)
        i = i / 256
        num -= 1
    if num < 0:
        raise UIn_BadParamError("Parameter is too large")
    while num > 0:
        byte_array.append(0)
        num -= 1
    byte_array.reverse()
    return byte_array

def parse_param(input_str, bitwidth):
    if bitwidth == 32:
        try:
            return ipv4Addr_to_bytes(input_str)
        except CLI_FormatExploreError:
            pass
        except UIn_BadIPv4Error:
            raise UIn_BadParamError("Invalid IPv4 address")
    elif bitwidth == 48:
        try:
            return macAddr_to_bytes(input_str)
        except CLI_FormatExploreError:
            pass
        except UIn_BadMacError:
            raise UIn_BadParamError("Invalid MAC address")
    elif bitwidth == 128:
        try:
            return ipv6Addr_to_bytes(input_str)
        except CLI_FormatExploreError:
            pass
        except UIn_BadIPv6Error:
            raise UIn_BadParamError("Invalid IPv6 address")
    try:
        input_ = int(input_str, 0)
    except:
        raise UIn_BadParamError(
            "Invalid input, could not cast to integer, try in hex with 0x prefix"
        )
    try:
        return int_to_bytes(input_, (bitwidth + 7) / 8)
    except UIn_BadParamError:
        raise

def parse_runtime_data(action, params):
    def parse_param_(field, bw):
        try:
            return parse_param(field, bw)
        except UIn_BadParamError as e:
            raise UIn_RuntimeDataError(
                "Error while parsing %s - %s" % (field, e)
            )

    bitwidths = [bw for( _, bw) in action.runtime_data]
    byte_array = []
    for input_str, bitwidth in zip(params, bitwidths):
        byte_array += [bytes_to_string(parse_param_(input_str, bitwidth))]
    return byte_array

_match_types_mapping = {
    MatchType.EXACT : BmMatchParamType.EXACT,
    MatchType.LPM : BmMatchParamType.LPM,
    MatchType.TERNARY : BmMatchParamType.TERNARY,
    MatchType.VALID : BmMatchParamType.VALID,
    MatchType.RANGE : BmMatchParamType.RANGE,
}

def parse_match_key(table, key_fields):

    def parse_param_(field, bw):
        try:
            return parse_param(field, bw)
        except UIn_BadParamError as e:
            raise UIn_MatchKeyError(
                "Error while parsing %s - %s" % (field, e)
            )

    params = []
    match_types = [t for (_, t, _) in table.key]
    bitwidths = [bw for (_, _, bw) in table.key]
    for idx, field in enumerate(key_fields):
        param_type = _match_types_mapping[match_types[idx]]
        bw = bitwidths[idx]
        if param_type == BmMatchParamType.EXACT:
            key = bytes_to_string(parse_param_(field, bw))
            param = BmMatchParam(type = param_type,
                                 exact = BmMatchParamExact(key))
        elif param_type == BmMatchParamType.LPM:
            prefix, length = field.split("/")
            key = bytes_to_string(parse_param_(prefix, bw))
            param = BmMatchParam(type = param_type,
                                 lpm = BmMatchParamLPM(key, int(length)))
        elif param_type == BmMatchParamType.TERNARY:
            key, mask = field.split("&&&")
            key = bytes_to_string(parse_param_(key, bw))
            mask = bytes_to_string(parse_param_(mask, bw))
            if len(mask) != len(key):
                raise UIn_MatchKeyError(
                    "Key and mask have different lengths in expression %s" % field
                )
            param = BmMatchParam(type = param_type,
                                 ternary = BmMatchParamTernary(key, mask))
        elif param_type == BmMatchParamType.VALID:
            key = bool(int(field))
            param = BmMatchParam(type = param_type,
                                 valid = BmMatchParamValid(key))
        elif param_type == BmMatchParamType.RANGE:
            start, end = field.split("->")
            start = bytes_to_string(parse_param_(start, bw))
            end = bytes_to_string(parse_param_(end, bw))
            if len(start) != len(end):
                raise UIn_MatchKeyError(
                    "start and end have different lengths in expression %s" % field
                )
            if start > end:
                raise UIn_MatchKeyError(
                    "start is less than end in expression %s" % field
                )
            param = BmMatchParam(type = param_type,
                                 range = BmMatchParamRange(start, end))
        else:
            assert(0)
        params.append(param)
    return params

def printable_byte_str(s):
    return ":".join("{:02x}".format(ord(c)) for c in s)

def BmMatchParam_to_str(self):
    return BmMatchParamType._VALUES_TO_NAMES[self.type] + "-" +\
        (self.exact.to_str() if self.exact else "") +\
        (self.lpm.to_str() if self.lpm else "") +\
        (self.ternary.to_str() if self.ternary else "") +\
        (self.valid.to_str() if self.valid else "") +\
        (self.range.to_str() if self.range else "")

def BmMatchParamExact_to_str(self):
    return printable_byte_str(self.key)

def BmMatchParamLPM_to_str(self):
    return printable_byte_str(self.key) + "/" + str(self.prefix_length)

def BmMatchParamTernary_to_str(self):
    return printable_byte_str(self.key) + " &&& " + printable_byte_str(self.mask)

def BmMatchParamValid_to_str(self):
    return ""

def BmMatchParamRange_to_str(self):
    return printable_byte_str(self.start) + " -> " + printable_byte_str(self.end_)

BmMatchParam.to_str = BmMatchParam_to_str
BmMatchParamExact.to_str = BmMatchParamExact_to_str
BmMatchParamLPM.to_str = BmMatchParamLPM_to_str
BmMatchParamTernary.to_str = BmMatchParamTernary_to_str
BmMatchParamValid.to_str = BmMatchParamValid_to_str
BmMatchParamRange.to_str = BmMatchParamRange_to_str

# services is [(service_name, client_class), ...]
def thrift_connect(thrift_ip, thrift_port, services):
    return utils.thrift_connect(thrift_ip, thrift_port, services)

def handle_bad_input(f):
    @wraps(f)
    def handle(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except UIn_MatchKeyError as e:
            print "Invalid match key:", e
        except UIn_RuntimeDataError as e:
            print "Invalid runtime data:", e
        except UIn_Error as e:
            print "Error:", e
        except InvalidTableOperation as e:
            error = TableOperationErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid table operation (%s)" % error
        except InvalidCounterOperation as e:
            error = CounterOperationErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid counter operation (%s)" % error
        except InvalidMeterOperation as e:
            error = MeterOperationErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid meter operation (%s)" % error
        except InvalidRegisterOperation as e:
            error = RegisterOperationErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid register operation (%s)" % error
        except InvalidLearnOperation as e:
            error = LearnOperationErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid learn operation (%s)" % error
        except InvalidSwapOperation as e:
            error = SwapOperationErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid swap operation (%s)" % error
        except InvalidDevMgrOperation as e:
            error = DevMgrErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid device manager operation (%s)" % error
        except InvalidCrcOperation as e:
            error = CrcErrorCode._VALUES_TO_NAMES[e.code]
            print "Invalid crc operation (%s)" % error
    return handle

def deprecated_act_prof(substitute, with_selection=False,
                        strictly_deprecated=True):
    # need two levels here because our decorator takes arguments
    def deprecated_act_prof_(f):
        # not sure if this is the right place for it, if I want it to play nice
        # with @wraps
        if strictly_deprecated:
            f.__doc__ = "[DEPRECATED!] " + f.__doc__
            f.__doc__ += "\nUse '{}' instead".format(substitute)
        @wraps(f)
        def wrapper(obj, line):
            substitute_fn = getattr(obj, "do_" + substitute)
            args = line.split()
            obj.at_least_n_args(args, 1)
            table_name = args[0]
            table = obj.get_res("table", table_name, TABLES)
            if with_selection:
                obj.check_indirect_ws(table)
            else:
                obj.check_indirect(table)
            assert(table.action_prof is not None)
            assert(table.action_prof.ref_cnt > 0)
            if strictly_deprecated and table.action_prof.ref_cnt > 1:
                raise UIn_Error(
                    "Legacy command does not work with shared action profiles")
            args[0] = table.action_prof.name
            if strictly_deprecated:
                # writing to stderr in case someone is parsing stdout
                sys.stderr.write(
                    "This is a deprecated command, use '{}' instead\n".format(
                        substitute))
            return substitute_fn(" ".join(args))
        # we add the handle_bad_input decorator "programatically"
        return handle_bad_input(wrapper)
    return deprecated_act_prof_

# thrift does not support unsigned integers
def hex_to_i16(h):
    x = int(h, 0)
    if (x > 0xFFFF):
        raise UIn_Error("Integer cannot fit within 16 bits")
    if (x > 0x7FFF): x-= 0x10000
    return x
def i16_to_hex(h):
    x = int(h)
    if (x & 0x8000): x+= 0x10000
    return x
def hex_to_i32(h):
    x = int(h, 0)
    if (x > 0xFFFFFFFF):
        raise UIn_Error("Integer cannot fit within 32 bits")
    if (x > 0x7FFFFFFF): x-= 0x100000000
    return x
def i32_to_hex(h):
    x = int(h)
    if (x & 0x80000000): x+= 0x100000000
    return x

def parse_bool(s):
    if s == "true" or s == "True":
        return True
    if s == "false" or s  == "False":
        return False
    try:
        s = int(s, 0)
        return bool(s)
    except:
        pass
    raise UIn_Error("Invalid bool parameter")

def create_switches(filename):

    json_data=open(filename)
    topo = json.load(json_data)
    switches = []
    for sw in topo['switches']:
        sw_id = sw['id']
        ip_addr = sw['ip_address']
        real_ip = sw['real_ip']
        port = sw['port']
        resp = sw['resp_network']
        routing_table = sw['routing_table']
        arp_table = sw['arp_table']
        ids_port = sw['ids_port']
        interfaces = sw['interfaces']
        ids_addr = sw['ids_addr']
    
        switch = Switch(sw_id, 
                        ip_addr,
                        real_ip,
                        port, 
                        resp,
                        interfaces,
                        ids_port, 
                        ids_addr,
                        routing_table,
                        arp_table)
        switches.append(switch)
    
    json_data.close() 
    return switches

class Switch():
    '''
        sw_id : Id of the switch
        ip_address: IP address used by the thrift server
        port : port used by thrift server
        resp : list of address that the switch handles
        interface: list of interface the switch (name:mac)
        ids_port: outport on the switch to reach the IDS
        ids_addr: ip address of IDS
        routing_table : dest ip : port
    '''
    def __init__(self, 
                 sw_id,
                 ip_addr,
                 real_ip,
                 port,
                 resp,
                 interfaces,
                 ids_port,
                 ids_addr,
                 routing_table,
                 arp_table):

        self.sw_id = sw_id
        self.ip_address = IPNetwork(ip_addr)
        self.real_ip = real_ip
        self.port = port
        self.resp = []
        for network in resp:
            ip_network = IPNetwork(network)
            self.resp.append(ip_network)
        self.interfaces = interfaces
        self.ids_port = ids_port
        self.ids_addr = ids_addr
        self.routing_table = routing_table
        self.arp_table = arp_table

    def is_responsible(self,ip_addr):
        r = False
        ip = IPAddress(ip_addr)
        for subnet in self.resp:
            if ip in subnet:
                r = True
                break
        return r

class Controller():


    @staticmethod
    def get_thrift_services(pre_type):
        services = [("standard", Standard.Client)]

        if pre_type == PreType.SimplePre:
            services += [("simple_pre",SimplePre.Client)]
        elif pre_type == PreType.SimplePreLAG:
            services += [("simple_pre_lag", SimplePreLAG.Client)]
        else:
            services += [(None, None)]

        return services

    def __init__(self):
        self.clients = {}
        self.switches = {}
        self.history = {}

    def add_client(self, id_client, standard_client, switch):
        self.clients[id_client] = standard_client
        self.switches[id_client] = switch

    def setup_connection(self, switches):
        once = True
        for sw in switches:
            standard_client, mc_client = thrift_connect(
                str(sw.ip_address.ip), int(sw.port), Controller.get_thrift_services(PreType.SimplePre)
            ) 
            if once:
                load_json_config(standard_client)
                once = False
            self.add_client(sw.sw_id, standard_client, sw)  

    def get_res(self, type_name, name, array):
        if name not in array:
            raise UIn_ResourceError(type_name, name)
        return array[name]

    def table_add_entry(self, client,table_name, action_name, match_key, action_params, prio=0):
        "Add entry to a match table: table_add <table name> <action name> <match fields> => <action parameters> [priority]"
        table = self.get_res("table", table_name, TABLES)
        if action_name not in table.actions:
            raise UIn_Error(
                "Table %s has no action %s" % (table_name, action_name)
            )
        
        if table.match_type in {MatchType.TERNARY, MatchType.RANGE}:
            try:
                priority = prio
            except:
                raise UIn_Error(
                    "Table is ternary, but could not extract a valid priority from args"
                )
        else:
            priority = 0
        
        # guaranteed to exist
        action = ACTIONS[action_name]
       
        if len(match_key) != table.num_key_fields():
            raise UIn_Error(
                "Table %s needs %d key fields" % (table_name, table.num_key_fields())
            )
        
        runtime_data = parse_runtime_data(action, action_params)
        
        match_key = parse_match_key(table, match_key)
        
        print "Adding entry to", MatchType.to_str(table.match_type), "match table", table_name
        
        
        entry_handle = client.bm_mt_add_entry(
            0, table_name, match_key, action_name, runtime_data,
            BmAddEntryOptions(priority = priority)
        )
        
        print "Entry has been added with handle", entry_handle

    def table_default_entry(self, client,table_name, action_name, action_params):
        table = self.get_res("table", table_name, TABLES)
        if action_name not in table.actions:
            raise UIn_Error(
                "Table %s has no action %s" % (table_name, action_name)
            )
        action = ACTIONS[action_name]
        if len(action_params) != action.num_params():
            raise UIn_Error(
                "Action %s needs %d parameters" % (action_name, action.num_params())
            )
        runtime_data = parse_runtime_data(action, action_params)
        client.bm_mt_set_default_action(0, table_name, action_name, runtime_data)

    def add_flow_id_entry(self, client, srcip, dstip, proto):
        self.table_add_entry(client, FLOW_ID, NO_OP,[srcip, dstip, proto],[])

    def add_modbus_entry(self, client, srcip, sport, funcode):
        self.table_add_entry(client, MODBUS, NO_OP, [srcip, sport, funcode],[])

    def add_ex_port_entry(self, client, srcip, dstip, sport, dport):
        self.table_add_entry(client, EX_PORT, NO_OP, [srcip, dstip, sport, dport],[])
    
    def add_send_frame_entry(self, client, port, mac):
        self.table_add_entry(client, SEND_FRAME, REWRITE, [port],[mac])
    
    def add_ipv4_entry(self, client, ip_addr, port):
        self.table_add_entry(client, IPV4_LPM, NHOP, [str(ip_addr)], [str(ip_addr.ip), port])

    def add_forward_entry(self, client, ip_addr, mac):
        self.table_add_entry(client, FORWARD, DMAC, [str(ip_addr)],[mac]) 
    
    def add_miss_tag_entry(self, client, tag, port):
        self.table_add_entry(client, MISS_TAG, REDIRECT, [tag],[port])

    def add_arp_resp_entry(self, client, ip_addr, mac):
        self.table_add_entry(client, ARP_RESP, RESP, [ip_addr],[mac])
    
    def add_arp_forw_entry(self, client, in_port, out_port):
        self.table_add_entry(client, ARP_FORW, REDIRECT, [in_port], [out_port])


    def get_resp_switch(self, srcip, dstip):
        #List of switch where the flow is passing
        resp_switch = [] 
        for switch in self.switches: 
            sw = self.switches[switch]
            if sw.is_responsible(srcip) or sw.is_responsible(dstip):
                resp_switch.append(sw)
        return resp_switch
               
    def deploy_flow_id_rules(self, resp_sw, srcip, dstip, protocol):
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            self.add_flow_id_entry(client, srcip, dstip, protocol)
            self.add_flow_id_entry(client, dstip, srcip, protocol) 

    def deploy_modbus_rules(self, resp_sw, srcip, sport, funcode):
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            self.add_modbus_entry(client, srcip, sport, funcode)

    def deploy_ex_port_rules(self, resp_sw, srcip, dstip, sport, dport):
        for sw in resp_sw:
            client = self.clients[sw.sw_id]
            self.add_ex_port_entry(client, srcip, dstip, sport, dport)
            self.add_ex_port_entry(client, dstip, srcip, dport, sport)

    def dessiminate_rules(self, filename):
        IP_PROTO_TCP = 6
        PSH = 0x08
        ACK = 0x10
        SYN = 0x02
        capture = rdpcap(filename)    
        for pkt in capture:
            srcip = pkt[IP].src
            dstip = pkt[IP].dst
            if pkt[IP].proto == IP_PROTO_TCP:
                proto = str(pkt[IP].proto)
                sport = str(pkt[TCP].sport)
                dport = str(pkt[TCP].dport)
                if not(self.history.has_key((srcip, dstip, proto, sport, dport)) or \
                        self.history.has_key((dstip, srcip, proto, dport, sport))):

                    resp_switch = self.get_resp_switch(srcip, dstip)  
                
                    self.history[(srcip, dstip, proto, sport, dport)] = resp_switch
                    self.history[(dstip, srcip, proto, dport, sport)] = resp_switch
                    self.deploy_flow_id_rules(resp_switch, srcip, dstip, proto)
                    self.deploy_ex_port_rules(resp_switch, srcip, dstip, sport, dport)

                flags = pkt[TCP].flags
                if (flags & PSH) and (flags & ACK) and (sport == "5020" or dport == "5020"):
                    funcode = str(pkt[ModbusHeader].funcode)
                    if not self.history.has_key((srcip, sport, funcode)):
                        resp_switch = self.history[(srcip, dstip, proto, sport, dport)]
                        self.deploy_modbus_rules(resp_switch, srcip, sport, funcode)
                        self.history[(srcip, sport, funcode)]=True

    def setup_default_entry(self):
        for switch in self.switches:
            sw = self.switches[switch]
            client = self.clients[sw.sw_id]
            is_ids_sw = sw.is_responsible(sw.ids_addr)

            self.table_default_entry(client, SEND_FRAME, DROP, [])
            self.table_default_entry(client, FORWARD, NO_OP, [])
            self.table_default_entry(client, IPV4_LPM, NO_OP, [])
            if not is_ids_sw:
                self.table_default_entry(client, FLOW_ID, ADD_TAG, [IP_MISS, sw.sw_id, sw.ids_addr, sw.ids_port])
                self.table_default_entry(client, EX_PORT, ADD_TAG, [PORT_MISS, sw.sw_id, sw.ids_addr, sw.ids_port])
                self.table_default_entry(client, MODBUS, ADD_TAG, [FUN_MISS, sw.sw_id, sw.ids_addr, sw.ids_port])

            self.table_default_entry(client, MISS_TAG, DROP, [])
            self.table_default_entry(client, ARP_RESP, NO_OP, [])
            self.table_default_entry(client, ARP_FORW, DROP, [])

            for interface in sw.interfaces:
                for iname in interface:
                    port = iname
                    mac = interface[iname]     
                    self.add_send_frame_entry(client, port, mac) 

            for arp_entry in sw.arp_table:
                for ip_addr in arp_entry:
                    mac = arp_entry[ip_addr]
                    self.add_forward_entry(client, ip_addr, mac) 

            for route in sw.routing_table:
                for dest in route:
                    port = route[dest]
                    self.add_ipv4_entry(client, IPNetwork(dest), port)

            for tag in [IP_MISS, PORT_MISS, FUN_MISS]:
                self.add_miss_tag_entry(client, tag, sw.ids_port) 
            ip_addr = sw.real_ip
            mac = sw.interfaces[0]["1"]
            self.add_arp_resp_entry(client, ip_addr, mac)
            self.add_arp_forw_entry(client, str(1), str(2))
            self.add_arp_forw_entry(client, str(2), str(1))



def load_json_config(standard_client=None, json_path=None):
    load_json_str(utils.get_json_config(standard_client, json_path))


def main(sw_config, capture):
    print "Creating switches"
    switches = create_switches(sw_config) 

    controller = Controller()
    print "Connecting to switches and setting default entry"
    controller.setup_connection(switches) 
    controller.setup_default_entry()
    print "Installing rules according to the capture"
    controller.dessiminate_rules(capture)

    #TODO wait for event

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--conf', action='store', dest='conf' ,help='file containing description of switch')
    parser.add_argument('--capture', action='store', dest='capture',help='training set capture for the whitelist')
    args = parser.parse_args()
    main(args.conf, args.capture)
