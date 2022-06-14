from scapy.all import DNS, DNSQR, IP, sr1, UDP

# dns_req = IP(dst='8.8.8.8')/UDP(dport=53)/ DNS(rd=1, qd=DNSQR(qname='www.stackoverflow.com'))
# answer = sr1(dns_req, verbose=0)

res = sniff(filter="dns", count =1)

print(answer[DNS].show())