from TcpAttack import *
#Your TcpAttack class should be named as TcpAttack
spoofIP="10.0.0.54" ; targetIP="10.0.0.229" #Will contain actual IP addresses in real script
rangeStart=0 ; rangeEnd=1024 ; port=80
Tcp = TcpAttack(spoofIP,targetIP)
# Tcp.scanTarget(rangeStart, rangeEnd)
if Tcp.attackTarget(port,10):
       print("port was open to attack")
else:
       print("port was not open to attack")