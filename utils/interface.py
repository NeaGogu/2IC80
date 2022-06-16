from dataclasses import dataclass


@dataclass
class InterfaceConfig:
  INTERFACE_NAME: str
  MAC_ADDR: str
  IP_ADDR: str 
  NETWORK_ADDRESS: str
   
   
interface_config = InterfaceConfig("eth0", "08:00:27:95:bd:54",
									   "192.168.56.169", "192.168.56.0/24")
