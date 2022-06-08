from scapy.all import *
from scapy.layers import *
import threading
import time
import socket

# Default variables
Net_Interface = "eth0" 


print("Select attack to perform on Victim who hates ducks: \n")
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

print("Set your Victim's IP")
VICTIM_IP = input()
print(VICTIM_IP)
