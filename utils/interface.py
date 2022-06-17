from dataclasses import dataclass, field
import dataclasses
from scapy.all import get_if_hwaddr, get_if_addr


@dataclass
class InterfaceConfig:
  INTERFACE_NAME: str
  MAC_ADDR: str = ""
  IP_ADDR: str = ""
  NETWORK_ADDRESS: str = ""
  
  def set_mac(self, iface: str):
    self.MAC_ADDR = get_if_hwaddr(iface )
  
  def set_ip(self, iface: str):
    self.IP_ADDR = get_if_addr(iface)
    
  def get_network_addr_from_ip(self):
    return ".".join(self.IP_ADDR.split(".")[:-1]) + ".0/24"
    
  def __post_init__(self):
    
    if not self.MAC_ADDR:
      self.set_mac(self.INTERFACE_NAME)
    if not self.IP_ADDR:
      self.set_ip(self.INTERFACE_NAME)
    if not self.NETWORK_ADDRESS:
      self.NETWORK_ADDRESS = self.get_network_addr_from_ip()
      
   
   
if __name__ == "__main__":
  print(InterfaceConfig("eth0", IP_ADDR="192.168.56.103" ))



