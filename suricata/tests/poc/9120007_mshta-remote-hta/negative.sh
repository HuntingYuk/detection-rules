#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# Exercises fast_pattern ("mshta" IS present) but as docs prose with no URL
# -> pcre rejects -> silent (§19 T6).
uri=b"/docs?q=mshta%20command%20syntax%20and%20parameters%20reference"
req=b"GET "+uri+b" HTTP/1.1\r\nHost: docs.example\r\nConnection: close\r\n\r\n"
S="10.0.0.97";D="10.0.0.80"
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=51096,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=51096,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
