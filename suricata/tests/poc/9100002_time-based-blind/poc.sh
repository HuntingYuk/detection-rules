#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
uri=b"/item?id=1%20AND%20sleep(5)--%20-"
S="10.0.0.33";pkts=[];t=1_700_000_000.0
for i in range(4):
    s=46300+i
    req=b"GET "+uri+b" HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"
    C=lambda f,q,a,p=b"",s=s:Ether()/IP(src=S,dst="10.0.0.80")/TCP(sport=s,dport=80,flags=f,seq=q,ack=a)/(Raw(p) if p else b"")
    V=lambda f,q,a,s=s:Ether()/IP(src="10.0.0.80",dst=S)/TCP(sport=80,dport=s,flags=f,seq=q,ack=a)
    fl=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
    for p in fl:p.time=t;t+=0.02
    pkts+=fl
wrpcap(sys.argv[1],pkts)
PY
