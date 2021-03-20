#!usr/bin/env python3

import socket
import argparse
import iptc

HOST='0.0.0.0'
PORT = 1234

def stop_responding():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT") 
    rule = iptc.Rule()
    rule.in_interface = "eth0"
    rule.src = "10.0.1.1/255.255.255.0"
    rule.protocol = "tcp"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)

    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
    rule = iptc.Rule()
    rule.out_interface = "eth0"
    rule.dst = "10.0.1.1/255.255.255.0"
    rule.protocol = "tcp"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain.insert_rule(rule)

def main(stop, nbr_pkt):
    nbr_packet = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        print("Starting server")
        s.listen()
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                nbr_packet += 1
                conn.sendall(data)
                if stop and nbr_packet >= nbr_pkt:
                    stop_responding()
                    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", action="store_true", default=False, dest="stop")
    parser.add_argument("-n", action="store", type=int, default=10, dest="nbr_pkt")

    args = parser.parse_args()
    main(args.stop, args.nbr_pkt)
