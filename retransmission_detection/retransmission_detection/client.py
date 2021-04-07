#!/usr/bin/env python

import socket
from time import sleep

HOST = '10.0.2.2'
DPORT = 1234
SPORT = 3333

BACKUP_HOST = '10.0.2.3'
BACKUP_SPORT = 3334

def run(host, sport, dport):
    error = False
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(3)
        s.bind(('', sport))
        s.connect((host, dport))
        for _ in range(15):
            nbr_timeout = 0
            while True:
                s.sendall(b'Hello, world')
                try:
                    data = s.recv(1024)
                    print('Received', repr(data))
                    break
                except socket.timeout:
                    print("Didn't receive data! [Timeout]")
                    nbr_timeout += 1
                    if nbr_timeout >= 5:
                        error = True
                        break
            if error:
                print("Contact with server lost")
                break
            sleep(1)
    return error

if run(HOST, SPORT, DPORT):
    print("Contacting backup server")
    run(BACKUP_HOST, BACKUP_SPORT, DPORT)
