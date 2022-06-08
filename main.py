from scapy.all import *
from scapy.layers import *
import threading
import time
import socket
import nmap
import os

# Default variables
Net_Interface = "eth0" 

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

if attack_to_perform == 1:
	arp()
	print("arp")
elif attack_to_perform == 2:
	dns()
	print("dns")
elif attack_to_perform == 3:
	arp()
	dns()
	print("arp and dns")

def arp():
	print("arp")

def dns():
	return


