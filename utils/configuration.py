from dataclasses import dataclass
import dataclasses
import json
import time
from rich.console import Console
from scapy.all import get_if_hwaddr, get_if_addr, get_if_list

from .interface import InterfaceConfig

console = Console()

class Config:
    def __init__(self, filename: str = "config.json") -> None:
        self._filename = filename
        self._interface_config = self.load_configuration_file(filename)
        
    def get_configuration(self):
        return self._interface_config

    def load_configuration_file(self, filename: str) -> InterfaceConfig:
        interface_config = None
        console.print(f"[yellow bold]Trying to read config file: [white underline]{self._filename}")

        with open(filename, 'a+') as f:
            try:
                # because a+ sets pointer at the end of the file
                f.seek(0) # needed for json to load correctly
                config = json.load(f)
                interface_config= InterfaceConfig(**config)
                console.print(f"[green bold][SUCCESS][/green bold]: [green italic]Successfully loaded config.json")
            except Exception as e:
                print(e)
                console.print("[red bold]Failed to parse [white underline on red]config.json[/white underline on red]! Falling back to default...")
                console.print(f"[red bold]Picking first working iface...")
                ifaces = get_if_list()
                
                if len(ifaces) < 2:
                    console.print("[red blink bold][WARNING][/red bold blink]: [magenta bold] NO INTERFACES DETECTED BESIDES [cyan italic]LOOPBACK[/cyan italic] ! EXITING PROGRAM...")
                    exit()
                    
                console.print(f"[blue bold]Picked [white underline]{ifaces[1]}[/white underline]. IP and MAC are set automatically")
                interface_config = InterfaceConfig(ifaces[1])
                
                with open(filename, "w") as f2:
                    json.dump(dataclasses.asdict(interface_config), f2)
            
                
            console.print(f"[cyan bold]Current config: {interface_config}")
        
        return interface_config
            

interface_config = Config().get_configuration()
time.sleep(3)
