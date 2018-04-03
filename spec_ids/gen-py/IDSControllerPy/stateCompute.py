#!/usr/bin/env python

import sys
import re
import yaml

from pyparsing import *
from Equation import Expression
from scapy.all import *
from struct import *
from utils import *



NUM_WEIGHT = 1
BOOL_WEIGHT = 5


class RequirementParser():

    def __init__(self):
        self.expr = self.create_parser()


    def create_parser(self):

        integer = Word(nums).setParseAction(lambda t:int(t[0]))
        variable = Word(alphas)
        operand = integer | variable
        
        expop = Literal('^')
        signop = oneOf('+ -')
        multop = oneOf('* /')
        plusop = oneOf('+ -')
        factop = Literal('!')
        andop = Literal('&')
        compop = oneOf('< > = <= =>')

        expr = operatorPrecedence( operand,
                                   [("!", 1, opAssoc.LEFT),
                                    ("^", 2, opAssoc.RIGHT),
                                    (signop, 1, opAssoc.RIGHT),
                                    (multop, 2, opAssoc.LEFT),
                                    (plusop, 2, opAssoc.LEFT),
                                    (compop, 2, opAssoc.LEFT),
                                    (andop, 2, opAssoc.LEFT),]
                                 )
        return expr

    def parse_requirement(self, requirement):
        return self.expr.parseString(requirement)

class State(): 

    def __init__(self, descFile, parser=RequirementParser()): 
        # name to variable 
        self.var = {}
        self.req = []
        self.parser = parser

        self.setup(descFile)

    def get_var_values(self):
        values = []
        for k,v in self.var.iteritems(): 
            values.append(v.value) 
        return values

    def count_numeric_var(self):
        return len(filter(lambda x: x.kind in [HOL_REG, INP_REG] ,self.var.values()))

    def setup(self, descFile):
        content = open(descFile).read()
        desc = yaml.load(content) 
        for var_desc in desc['variables']:
            var = var_desc['variable']
            pv = ProcessVariable(var['host'],
                                 var['port'],
                                 var['type'],
                                 var['address'],
                                 var['size'],
                                 var['name']) 
            self.var[pv.name] = pv 
        
        for req_desc in desc['requirements']:
            self.req.append(self.parser.parse_requirement(req_desc['requirement'])) 
            
        
    def add_variable(self, host, port, kind, addr, name): 
        self.var[name] = ProcessVariable(host, port, kind, addr, size, name)

    def compute_distance(self, req, dist, max_depth=50):
        eq = ""
        acc = []
        if max_depth > 0:
            for lit in req:
                # FIXME variable in requirements 
                if isinstance(lit, collections.Iterable) and type(lit) is not str:
                    res = self.compute_distance(lit, dist, max_depth-1)
                    eq += str(res)
                elif lit in [">", "=", "<"]:
                    if is_number(eq):
                        acc.append(int(eq))
                    else:
                        eq = ""
                elif lit == "&":
                    eq = ""
                else:
                    eq += str(lit)
            resp = Expression(eq,self.var.keys())
            if len(acc) > 0:
                if type(acc[0]) is int:
                    d = abs(acc[0] - int(eq))
                else:
                    var = self.var[acc[0]]
                    d = abs(var.value - int(eq))
                    d = NUM_WEIGHT*d if var.kind is in [DIS_COIL, DIS_INP] else BOOL_WEIGHT*d
                dist.append(d)
            return resp(*self.get_var_values())

    def get_req_distance(self):
       
        min_dist = None
        num_var = self.count_numeric_vars()
        bool_var = len(self.var) - num_numeric_var
        for requirement in self.req: 
            dist = [] 
            self.compute_distance(requirement, dist)
            if min_dist is None:
                min_dist = float(sum(dist))/(NUM_WEIGHT*num_var + BOOL_WEIGHT*bool_var)
            else:
                d = float(sum(dist))/(NUM_WEIGHT*num_var + BOOL_WEIGHT*bool_var)
                min_dist = min(min_dist, d)

        return min_dist


    def update_var_from_packet(self, name, funcode, payload):
        print name
        val = payload.getfieldval(func_fields_dict[funcode])
        if type(val) is list:
            val = val[0]
        print val 
        self.update_value(name, val)

    def update_value(self, name, value):
        self.var[name].value = value
        

