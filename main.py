from scapy import get_if_list

from attacks import arp_poisoning

# We define the settings here which are to be altered by the attacker when chosing the way 
# the attack is to be done. Current values contain some default settings
settings = {"interrupted":False, "interfaces":[], "restore_arp_cache": True}

def start_attack(0:
    print("Choose interfaces you would like to (discover and) attack")

if __name__ == 'main':
    try:
        start_attack()
    except KeyboardInterrupt: #in case attacker stops terminal execution with Ctrl+c
        settings["interrupted"] = True
        print("Attack stopped... Checking for settings if arp cache is to be restored...")
        if settings["restore_arp_cache"]:
            arp_poisoning.restore()#FU have fix this
        
