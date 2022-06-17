from dataclasses import dataclass
import dataclasses
import json
from rich.console import Console
from scapy.all import get_if_hwaddr, get_if_addr, get_if_list

from interface import InterfaceConfig

console = Console()
interface_config = None

# with open("config.json", "w") as f:
#     json.dump(dataclasses.asdict(interface_config), f)

with open("config.json", 'r') as f:
    config = json.load(f)

    try:
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
        
        with open("config.json", "w") as f2:
            json.dump(dataclasses.asdict(interface_config), f2)
    
        
    console.print(f"[cyan bold]Current config: {interface_config}")
        
    



