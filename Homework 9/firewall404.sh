#!/bin/sh

# Homework Number: 9
# Name: Jose Luis Tejada
# ECN Login: tejada
# Due Date: Thursday 4/02/2020 at 4:29PM

#Remove any previous rules or chains by flushing
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t raw -F
sudo iptables -t raw -X


#TODO: Change their source IP address to your own machine’s IP address
sudo iptables -t nat -A POSTROUTING -j MASQUERADE


#Block a list of specific IP addresses (of your choosing : Blocks 155.126.21.92 and 57.11.13.78) for all incoming connections.
sudo iptables -A INPUT -s 155.126.21.92/57.11.13.78 -j DROP

#Block your computer from being pinged by all other hosts 
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

#Set up port-forwarding from an unused port of your choice to port 22 on your computer.
#Enable connections on the unused port
sudo iptables -t nat -A PREROUTING -p tcp --dport 60606 -j DNAT --to 128.58.10.100:22
sudo iptables -t nat -A PREROUTING -p tcp --dport 60606 -j DNAT
sudo iptables -A FORWARD -p tcp --dport 22 -j ACCEPT

#Allow for SSH access (port 22) to your machine from only the engineering.purdue.edu domain.
sudo iptables -A INPUT -s engineering.purdue.edu -p tcp --dport 22 -j ACCEPT

#Allows only a single IP address in the internet to access your machine for the HTTP service.
sudo iptables -A INPUT --dport 80 -s ! 192.168.0.116 -j REJECT

#Permit Auth/Ident (port 113) that is used by some services like SMTP and IRC.
sudo iptables -A INPUT -p tcp --destination-port 113 -j ACCEPT
