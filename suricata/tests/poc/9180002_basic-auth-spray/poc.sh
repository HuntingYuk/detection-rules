#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys,base64
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# Threshold 30/60s by_src EXCEEDS — send 31 Basic-auth requests from one src.
S="10.0.0.64";pkts=[];t=1_700_000_000.0
for i in range(31):
    s=44700+i
    cred=base64.b64encode(("admin:p%dWord" % i).encode()).decode()
    req=("GET /admin HTTP/1.1\r\nHost: app.example\r\nAuthorization: Basic "+cred+
         "\r\nConnection: close\r\n\r\n").encode()
    C=lambda f,q,a,p=b"",s=s:Ether()/IP(src=S,dst="10.0.0.80")/TCP(sport=s,dport=80,flags=f,seq=q,ack=a)/(Raw(p) if p else b"")
    V=lambda f,q,a,s=s:Ether()/IP(src="10.0.0.80",dst=S)/TCP(sport=80,dport=s,flags=f,seq=q,ack=a)
    fl=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
    for p in fl:p.time=t;t+=0.01
    pkts+=fl
wrpcap(sys.argv[1],pkts)
PY
