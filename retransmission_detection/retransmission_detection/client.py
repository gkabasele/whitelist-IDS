#!/usr/bin/env python3

import socket
import argparse
import random
import threading
import logging
from time import sleep


HOST = '10.0.2.2'
DPORT = 1234
DUMBPORT = 1235
SPORT = 3333

BACKUP_HOST = '10.0.2.3'
BACKUP_SPORT = 3334

def run(host, dport, crash, nb_pkt, sport=None):
    error = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        if sport is not None:
            s.bind(('', sport))
        s.connect((host, dport))
        for _ in range(nb_pkt):
            nbr_timeout = 0
            while True:
                s.sendall(b'Hello, world')
                try:
                    data = s.recv(1024)
                    print('Received from {}:{}'.format(host, dport), repr(data))
                    logging.debug('Received from {}:{}'.format(host, dport), repr(data))
                    break
                except socket.timeout:
                    print("Didn't receive data! [Timeout]")
                    logging.debug("Didn't receive data! [Timeout]")
                    nbr_timeout += 1
                    if nbr_timeout >= crash:
                        error = True
                        break
            if error:
                print("Contact with server lost")
                logging.debug("Contact with server lost")
                break
            sleep(1)
    return error

def main(server, dport, sport, bserver, dumb_port, crash, nb_pkt): 
    print("Contacting server") 
    logging.debug("Contacting server")
    if run(server, dport, crash, nb_pkt, sport):
        print("Contacting backup server")
        logging.debug("Contacting backup server")
        t1 = threading.Thread(target=run, args=(bserver, dport, crash, nb_pkt))
        print("Creating dumb flow")
        logging.debug("Creating dumb flow")
        t2 = threading.Thread(target=run, args=(bserver, dumb_port, crash, nb_pkt))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dport", action="store", type=int, default=DPORT, dest="dport")
    parser.add_argument("--sport", action="store", type=int, default=SPORT, dest="sport")
    parser.add_argument("--server", action="store", type=str, default=HOST, dest="server")
    parser.add_argument("--bserver", action="store", type=str, default=BACKUP_HOST, dest="bserver")
    parser.add_argument("--dumbport", action="store", type=int, default=DUMBPORT, dest="dumb_port")
    parser.add_argument("--crash", action="store", type=int, default=3, dest="crash")
    parser.add_argument("--nb", action="store", type=int, default=15, dest="nb_pkt")

    logging.basicConfig(filename="logs/client.log", level=logging.DEBUG)
    args = parser.parse_args()
    main(args.server, args.dport, args.sport,
         args.bserver,args.dumb_port, args.crash, args.nb_pkt)
