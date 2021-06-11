import argparse
import os
import pdb
import matplotlib.pyplot as plt
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
            
def get_conn_from_dir(dirname):
    conns = dict()

    for f in os.listdir(dirname):
        filename = os.path.join(dirname,f)
        print(filename)
        packets = rdpcap(filename)
        get_conn_time(packets, conns)

    return conns

def main(proactive_dir,
         no_proactive_dir,
         outfile):
    
    conns_proactive = get_conn_from_dir(proactive_dir)
    conns_no_proactive = get_conn_from_dir(no_proactive_dir)

    backup_flow = ("10.0.1.1", "10.0.2.3", 1234)
    redirected_flow = ("10.0.1.1", "10.0.2.3", 1235)

    proactive_backup = conns_proactive[backup_flow]
    no_proactive_backup = conns_no_proactive[backup_flow]
    no_proactive_redirected = conns_no_proactive[redirected_flow]
    
    fig1, ax1 = plt.subplots()
    ax1.set_title("Connection establishment time")
    ax1.boxplot([proactive_backup, no_proactive_backup, no_proactive_redirected])
   
    plt.show() 

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", type=str, action="store",
                        dest="proactive_dir")
    parser.add_argument("-n", type=str, action="store",
                        dest="no_proactive_dir")

    parser.add_argument("-o", type=str, action="store",
                        dest="outfile")

    args = parser.parse_args()
    main(args.proactive_dir, args.no_proactive_dir, args.outfile)
