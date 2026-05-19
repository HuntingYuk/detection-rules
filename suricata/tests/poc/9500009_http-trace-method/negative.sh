#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
req=b"GET /index.html HTTP/1.1\r\nHost: shop.example\r\nConnection: close\r\n\r\n"
SRC="10.0.0.71"; D="10.0.0.80"
C=lambda f,s,a,p=b"":Ether()/IP(src=SRC,dst=D)/TCP(sport=51020,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=SRC)/TCP(sport=80,dport=51020,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk: p.time=t; t+=0.01
wrpcap(sys.argv[1],pk)
PY
