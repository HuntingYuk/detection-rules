#!/usr/bin/env python3
# Provenance generator for the dns-tunnel golden fixtures (spec §19 T3).
# Re-run to regenerate deterministically. Requires scapy.
import hashlib, os, sys
from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR
HERE=os.path.dirname(os.path.abspath(__file__))
def q(src, qname, t):
    p=Ether()/IP(src=src,dst="10.0.0.53")/UDP(sport=40000,dport=53)/DNS(rd=1,qd=DNSQR(qname=qname))
    p.time=t; return p
# poc: 20 long-hex-label queries from ONE src -> trips detection_filter count 15
poc=[]; t=1_700_000_000.0
for i in range(20):
    h=hashlib.sha256(b"tunnel%d"%i).hexdigest()[:56]   # 56 hex chars (>=48, <=63)
    poc.append(q("10.0.0.9", f"{h}.tunnel.example", t)); t+=0.2
wrpcap(os.path.join(HERE,"poc.pcap"), poc)
# benign: normal queries + ONE long-hex label (matches pcre once, below threshold)
ben=[q("10.0.0.60","www.example.com",t),
     q("10.0.0.60","cdn.assets.example.net",t+0.1),
     q("10.0.0.60","api.shop.example",t+0.2),
     q("10.0.0.60", hashlib.sha256(b"x").hexdigest()[:50]+".legit-but-long.example", t+0.3)]
wrpcap(os.path.join(HERE,"benign.pcap"), ben)
print("wrote poc.pcap (%d pkts) benign.pcap (%d pkts)"%(len(poc),len(ben)))
