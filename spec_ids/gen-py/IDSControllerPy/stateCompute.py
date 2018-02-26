import sys
import re

from pyparsing import *
from Equation import Expression
from scapy.all import *
from struct import *
from utils import *





class RequirementParser():

    def __init__(self):
        self.expr = self.create_parser()


    def create_parser(self):

        integer = Word(nums).setParseAction(lambda t:int(t[0]))
        variable = Word(alphas,exact=1)
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

    def __init__(self, reqFile, varFile ): 
        # name to variable 
        self.var = {}
        self.req = []

    def get_var_values(self):
        values = []
        for k,v in self.var.iteritems(): 
            values.appends(v.value) 
        return values

    def setup_var(self, varFile):
        with open(varFile,'r') as f:
            for line in f:
                varname = re.search('.+\[', line).group(0).strip('[')
                (ip, port, kind, addr, size) = re.search('\[.+\]', line).group(0).strip('[]').split(':')
                self.var[varname] = ProcessVariable(host, port, kind, addr, size, varname)

    def setup_req(self, reqFile):
        with open(reqFile, 'r') as f:
            for line in f:
                self.req.append(req)   

    def add_variable(self, host, port, kind, addr, name): 
        self.var[name] = ProcessVariable(host, port, kind, addr, size, name)

    def compute_distance(req, dist, max_depth=50):
        eq = ""
        acc = []
        if max_depth > 0:
            for lit in req:
                # FIXME variable in requirements 
                if isinstance(lit, collections.Iterable) and type(lit) is not str:
                    res = compute_distance(lit, dist, max_depth-1)
                    eq += str(res)
                elif lit in [">", "=", "<"]:
                    acc.append(int(eq))
                    eq = ""
                elif lit == "&":
                    eq = ""
                else:
                    eq += str(lit)
            resp = Expression(eq,self.var.keys())
            if len(acc) > 0:
                d = abs(acc[0] - int(eq))
                dist.append(d)
            return resp(*self.get_var_values())
        

