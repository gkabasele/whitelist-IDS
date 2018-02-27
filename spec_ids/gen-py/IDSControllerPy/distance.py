#
# simpleArith.py
#
# Example of defining an arithmetic expression parser using
# the operatorGrammar helper method in pyparsing.
#
# Copyright 2006, by Paul McGuire
#

from pyparsing import *
from Equation import Expression
import collections
import re

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

# To use the operatorGrammar helper:
#   1.  Define the "atom" operand term of the grammar.
#       For this simple grammar, the smallest operand is either
#       and integer or a variable.  This will be the first argument
#       to the operatorGrammar method.
#   2.  Define a list of tuples for each level of operator
#       precendence.  Each tuple is of the form
#       (opExpr, numTerms, rightLeftAssoc, parseAction), where
#       - opExpr is the pyparsing expression for the operator;
#          may also be a string, which will be converted to a Literal
#       - numTerms is the number of terms for this operator (must
#          be 1 or 2)
#       - rightLeftAssoc is the indicator whether the operator is
#          right or left associative, using the pyparsing-defined
#          constants opAssoc.RIGHT and opAssoc.LEFT.
#       - parseAction is the parse action to be associated with 
#          expressions matching this operator expression (the
#          parse action tuple member may be omitted)
#   3.  Call operatorGrammar passing the operand expression and
#       the operator precedence list, and save the returned value
#       as the generated pyparsing expression.  You can then use
#       this expression to parse input strings, or incorporate it
#       into a larger, more complex grammar.
#       
expr = operatorPrecedence( operand,
    [("!", 1, opAssoc.LEFT),
     ("^", 2, opAssoc.RIGHT),
     (signop, 1, opAssoc.RIGHT),
     (multop, 2, opAssoc.LEFT),
     (plusop, 2, opAssoc.LEFT),
     (compop, 2, opAssoc.LEFT),
     (andop, 2, opAssoc.LEFT),]
    )

def eval_expr(expr, dist, variables, values, max_depth = 50):
    eq = ""
    acc = []
    if max_depth > 0:
        for lit in expr:
            if isinstance(lit, collections.Iterable) and type(lit) is not str:
                res = eval_expr(lit, dist, variables, values, max_depth-1)
                eq += str(res)
            elif lit in [">","=","<"]:
                acc.append(int(eq))
                eq = ""
            elif lit == "&":
                eq = ""
            else:
                eq += str(lit)
        resp = Expression(eq, variables)
        if len(acc) > 0:
            #d = abs(acc[0] - int(eq))
            d = acc[0] - int(eq)
            dist.append(d)
            print "Dist: ",d
        return resp(*values)
    else:
        return


test = "2*a + 4*b < 100"
res = expr.parseString(test)
variables = ["a", "b"]
values = [1, 2]
dist = []
print "Req: %s value: %s"% (test, values)
eval_expr(res, dist, variables, values, max_depth=50) 
print sum(dist)

values = [40, 12]
dist = []
print "Req: %s value: %s"% (test, values)
eval_expr(res, dist, variables, values, max_depth=50) 
print sum(dist)

'''
test1 = "2*5 + 4*3 < 100"
res =  expr.parseString(test1)
d1 = []
print "Req: ", test1
eval_expr(res, d1)
print sum(d1)

test2 = "2*5 + 4*3 < 10*3 + 2*6"
res = expr.parseString(test2)
d2 = []
print "Req: ", test2
eval_expr(res, d2)
print sum(d2)

test3 = "2*5 + 4*3 < 10*3 + 2*6 & 3 + 2 < 7"
res = expr.parseString(test3)
d3 = []
print "Req: ", test3
eval_expr(res, d3)
print sum(d3)

test4 = "2*5 + 4*3 < 10*3 + 2*6 & 3*5 + 9*2 > 4*5 + 5*3"
res = expr.parseString(test4)
d4 = []
print "Req: ", test4
eval_expr(res, d4)
print sum(d4)

test5 = "2*5 + 4*3 < 10*3 + 2*6 & 3*5 + 9*2 > 4*5 + 5*3 & 2*4 > 5*8"
res = expr.parseString(test5)
d5 = []
print "Req: ", test5
eval_expr(res, d5)
print sum(d5)

test6 = "(1+3)*2 < 10"
res = expr.parseString(test6)
d6 = []
eval_expr(res, d6)
print sum(d6)
'''
