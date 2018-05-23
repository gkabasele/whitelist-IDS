#!/usr/bin/env python

import sys
import os
import re
import yaml
import logging

from pyparsing import *
from Equation import Expression
from scapy.all import *
from struct import *
from utils import *

from req_interpreter.lexer import Lexer
from req_interpreter.parser import Parser
from req_interpreter.interpreter import Interpreter

NUM_WEIGHT = 1
BOOL_WEIGHT = 5

logger = logging.getLogger('__name__')


class Requirement():

    identifier = 0

    def __init__(self, content):

        self.identifier = Requirement.identifier
        Requirement.identifier += 1
        self.content = content

class State(): 

    def __init__(self, descFile): 
        # name to variable
        self.var = {}
        self.req = []

        self.setup(descFile)

    def get_var_values(self):
        values = []
        for k, v in self.var.iteritems(): 
            values.append(v.value)
        return values

    def count_bool_var(self):
        return len(filter(lambda x: x.is_bool_var(), self.var.values()))

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
            req = Requirement(Parser(Lexer(req_desc['requirement'])).parse())
            self.req.append(req)

    def add_variable(self, host, port, kind, addr, size, name): 
        self.var[name] = ProcessVariable(host, port, kind, addr, size, name)

    def get_min_distance(self):

        min_dist = None
        identifier = None
        bool_var = self.count_bool_var()
        num_var = len(self.var) - bool_var

        for requirement in self.req:
            tmp = min_dist
            i = Interpreter(None, self.var, NUM_WEIGHT, BOOL_WEIGHT)
            violation = i.visit(requirement.content)
            if violation:
                logger.warn("The critical property {} is satisfied!!".format(requirement.identifier))
            if min_dist is None:
                min_dist = i.compute_distance(num_var, bool_var)
                identifier = requirement.identifier
            else:
                d = i.compute_distance(num_var, bool_var) 
                min_dist = min(min_dist, d)
                identifier = requirement.identifier if tmp != min_dist else identifier

        return identifier, min_dist

    def get_max_distance(self):

        max_dist = None
        at_least_one = False
        identifier = None
        bool_var = self.count_bool_var()
        num_var = len(self.var) - bool_var

        for requirement in self.req:
            tmp = max_dist
            i = Interpreter(None, self.var, NUM_WEIGHT, BOOL_WEIGHT)
            req = i.visit(requirement.content)
            print i.distances
            at_least_one = (at_least_one or req)

            if max_dist is None:
                max_dist = i.compute_distance(num_var, bool_var, False)
                identifier = requirement.identifier
            else:
                d = i.compute_distance(num_var, bool_var)
                max_dist = max(max_dist, d)
                identifier = requirement.identifier if tmp != max_dist else identifier

        if not at_least_one:
            logger.warn("No requirement were satisfy!")

        return identifier, max_dist


    def update_var_from_packet(self, name, funcode, payload):
        val = payload.getfieldval(func_fields_dict[funcode])
        if type(val) is list:
            val = val[0]
        if self.var[name].is_bool_var():
            val = 1 if val > 0 else 0

        logger.info("Updating var {} to {}".format(name, val))
        self.var[name].value = val

