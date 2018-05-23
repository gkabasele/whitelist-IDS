import os 
import re
import ast
import argparse
from tabulate import tabulate

# Regex used to match relevant loglines
line_regex = re.compile("\{.+\}")

states = []
index = len('[2018-05-08 15:21:11,742][INFO][/home/mininet/p4-tutorials/whitelist/mininet/physical_process/medium-process/mtu_med.py-60] ')
i = len('[2018-05-08 15:21:11,310] [INFO]:')

parser = argparse.ArgumentParser()
parser.add_argument("--format", dest="format", choices=['csv', 'table'], default="csv", action="store")
parser.add_argument("--output", dest="output", default="state.txt", action="store")
args = parser.parse_args()

with open(args.output, "w") as out:
   out.write("") 

with open(args.output,"a") as out:
    with open("ics.log", "r") as f:
        for line in f:
            if (line_regex.search(line)):
                if 'None' not in line:
                    s = ast.literal_eval(line[index:])
                    states.append(s)

    with open("logs/ids_spec.log", "r") as f:
        ids = [] 
        dist = []
        for line in f:
            if 'ID:' in line:
                val = line[i:].split(" ")
                ids.append(val[1])
                dist.append(val[3])

    if args.format =='table':
        headers = states[0].keys() + [("ID"), ("Dist")]
        rows = []
        for i, line in enumerate(states):
            # Must ignore the first state because the ids was not enable yet
            if i > 0:
                if i < len(ids):
                    rows.append(line.values() + [ids[i-1], dist[i-1]])
        out.write(tabulate(rows, headers=headers))

    if args.format == 'csv':
        # csv format
        out.write("#")
        for k in states[0].keys() + [("ID"), ("Dist")]:
            out.write("{},".format(k))

        for i, line in enumerate(states):
            # Same reason as stated before
            if i > 0:
                out.write("{},".format(i-1))
                if i < len(ids):
                    for v in line.values():
                        out.write("{},".format(v))
                    out.write("{},".format(ids[i-1]))
                    out.write("{}".format(dist[i-1]))
