import argparse
import os
import pdb
from scapy.all import *

FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10


START = "start"
END = "end"

def get_conn_time(packets, conns):

    map_syn_ack = dict()
    clients= set()
    for p in packets:
        if p.haslayer(TCP):
            saddr = p[IP].src
            daddr = p[IP].dst
            sport = p[TCP].sport
            dport = p[TCP].dport
            flags = p[TCP].flags
            key = (saddr, daddr, dport)
            if (flags & SYN) and not (flags & ACK):
                map_syn_ack[key] = {START:p.time,
                                    END: None}
                clients.add((saddr, sport))
            elif ((flags & ACK) and 
                  (not((flags & SYN) or (flags & PSH) or (flags & FIN)))):
                if (saddr, sport) not in clients:
                    continue
                if map_syn_ack[key][END] is None:
                    map_syn_ack[key][END] = p.time
                    diff = map_syn_ack[key][END] - map_syn_ack[key][START]
                    if key in conns:
                        conns[key].append(diff)
                    else:
                        conns[key] = [diff]
            

def main(indir, outfile):
    conns = dict()

    for f in os.listdir(indir):
        filename = os.path.join(indir,f)
        print(filename)
        packets = rdpcap(filename)
        get_conn_time(packets, conns)

    print(conns)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", type=str, action="store",
                        dest="indir")

    parser.add_argument("-o", type=str, action="store",
                        dest="outfile")

    args = parser.parse_args()
    main(args.indir, args.outfile)
