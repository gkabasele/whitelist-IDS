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
parser.add_argument("--format", dest="format", default="csv", action="store")
args = parser.parse_args()

with open("state.txt", "w") as out:
   out.write("") 

with open("state.txt","a") as out:
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
            if i < len(ids):
                rows.append(line.values() + [ids[i], dist[i]])
        out.write(tabulate(rows, headers=headers))

    if args.format == 'csv':
        # csv format
        for k in states[0].keys() + [("ID"), ("Dist")]:
            out.write("%s," % k)

        for i, line in enumerate(states):
            out.write("\n")
            if i < len(ids):
                for v in line.values():
                    out.write("%s," % v)
                out.write("%s, " % ids[i])
                out.write("%s" % dist[i])
