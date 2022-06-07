from scapy.arch import get_if_list
from time import sleep

import arp_poisoning, randomducks

# We define the settings here which are to be altered by the attacker when chosing the way 
# the attack is to be done. Current values contain some default settings
settings = {"interrupted":False, "interfaces":[], "restore_arp_cache": True}

def start_attack():
    print("Choose interfaces you would like to (discover and) attack")
    interfaces = get_if_list()
    interface_sets = makeInterfacePowersets(interfaces)
    settings["interfaces"] = interface_sets
    print (interface_sets)
   
    return

if __name__ == 'main':
    try:
        start_attack()
    except KeyboardInterrupt: #in case attacker stops terminal execution with Ctrl+c
        settings["interrupted"] = True
        print("Attack stopped... Checking for settings if arp cache is to be restored...")
        if settings["restore_arp_cache"]:
            for interface in settings["interface"]:
                arp_poisoning.restore(interface, settings)#FU have fix this
        
