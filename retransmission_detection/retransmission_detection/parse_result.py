#!/usr/bin/env python3

import argparse
import os
import sys
import matplotlib.pyplot as plt

BACKUP_SERVER = "10.0.2.3"
SERVER_PORT = "1234"
OTHER_PORT = "1235"
BACKUP = "backup"
OTHER = "other"

def get_host(line):
    tmp = line.split(":")
    host = tmp[1].replace(" ", "")
    host += "-" + tmp[2].strip()
    return host


def parse_file(filename):
    infos = dict()
    found_conn = False
    host_a = None
    host_b = None
    for line in filename:
        if "host" in line and not found_conn:
            found_conn = True
            host_a = get_host(line)
        elif "host" in line and found_conn:
            host_b = get_host(line)
        elif found_conn and "avg" in line:
            tmp = line.split(":")
            avg_a = float(tmp[1].replace(" ","").replace("ms","").replace("RTTavg", "").strip())
            avg_b = float(tmp[2].replace(" ","").replace("ms","").strip())
            if SERVER_PORT in host_b and BACKUP_SERVER in host_b:
                infos[BACKUP] = avg_a
            elif OTHER_PORT in host_b and BACKUP_SERVER in host_b:
                infos[OTHER] = avg_a
            found_conn = False
    return infos


def main(inputdir, outputfile):
    back_up_flows_rtt = list()
    other_flows_rtt = list()
    for file_res in os.listdir(inputdir):
        print("Starting %s" % file_res)
        with open(os.path.join(inputdir, file_res), "r") as f:
            infos = parse_file(f)
            back_up_flows_rtt.append(infos[BACKUP])
            other_flows_rtt.append(infos[OTHER])
    fig1, ax1 = plt.subplots()
    ax1.set_ylabel("ms")
    ax1.set_xlabel("Type of Flow(left:back up, right:normal)")
    ax1.set_title("RTT average")
    ax1.boxplot([back_up_flows_rtt, other_flows_rtt])
    plt.show()
    

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", action="store", type=str, dest="inputdir")
    parser.add_argument("-w", action="store", type=str, dest="outputfile")

    args = parser.parse_args()

    main(args.inputdir, args.outputfile)
