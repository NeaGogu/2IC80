# 2IC80

# Goal

Tool for:

- ARP <- malaka christoforos
- DNS spoofing <- stavros
- SSL stripping <- romanian

Should have different modalities that automatically poisons arp caches and uses DNS queries to poison recursive DNS cache/implements a mitm attack on ssl channel

# Ideas

## ARP

1. prompt to choose interface -> discover hosts
2. forward packets or no?
3. restore ARP caches ?

## DNS

1. Ask to type which domain to spoof?
2. Choose which IP to redirect spoofed domain/

## SSL Strip
