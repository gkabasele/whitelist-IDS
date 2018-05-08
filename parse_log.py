import os 
import re
import ast
import argparse
from tabulate import tabulate

# Regex used to match relevant loglines
line_regex = re.compile("\{.+\}")

lines = []
index = len('[2018-05-08 15:21:11,742][INFO][/home/mininet/p4-tutorials/whitelist/mininet/physical_process/medium-process/mtu_med.py-60] ')

parser = argparse.ArgumentParser()
parser.add_argument("--format", dest="format", default="csv", action="store")
args = parser.parse_args()

with open("state.txt", "w") as out:
   out.write("") 

with open("state.txt","a") as out:
    with open("ics.log", "r") as f:
        for line in f:
            if (line_regex.search(line)):
                if 'None' not in line:
                    varmap = ast.literal_eval(line[index:])
                    lines.append(varmap)

    if args.format =='table':
        headers = lines[0].keys()
        rows = []
        for line in lines:
            rows.append(line.values())
        out.write(tabulate(rows, headers=headers))

    if args.format == 'csv':
        # csv format
        for k in lines[0].keys():
            out.write("%s," % k)

        for line in lines:
            out.write("\n")
            for v in line.values():
                out.write("%s," % v)

