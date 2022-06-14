from dataclasses import dataclass


@dataclass
class InterfaceConfig:
  INTERFACE_NAME: str
  MAC_ADDR: str
  IP_ADDR: str 
   