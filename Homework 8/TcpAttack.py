#!/usr/bin/env python3

import sys, socket
from scapy.all import *

class TcpAttack:
    # spoofIP: String containing the IP address to spoof
    # targetIP: String containing the IP address of the target computer to attack
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP


    # rangeStart: Integer designating the first port in the range of ports being scanned.
    # rangeEnd: Integer designating the last port in the range of ports being scanned
    # No return value, but writes open ports to openports.txt
    def scanTarget(self, rangeStart, rangeEnd):
        with open('openports.txt', 'w') as out_file:
            for port in range(rangeStart, rangeEnd+1):
                sock_i = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # (7)
                sock_i.settimeout(0.1)
                print(port)
                if not sock_i.connect_ex((self.targetIP, port)):
                    out_file.write(str(port) + '\n')
        out_file.close()
        return


    # port: Integer designating the port that the attack will use
    # numSyn: Integer of SYN packets to send to target IP address at the given port
    #If the port is open, perform DoS attack and return 1. Otherwise return 0.
    def attackTarget(self, port, numSyn):
        return