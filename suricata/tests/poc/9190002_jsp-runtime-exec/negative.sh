#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
body=b"title=My%20Java%20notes&body=Runtime%20performance%20of%20exec%20pipelines"
req=b"POST /blog/new HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.119"
C=lambda f,q,a,p=b"":Ether()/IP(src=S,dst="10.0.0.80")/TCP(sport=55700,dport=80,flags=f,seq=q,ack=a)/(Raw(p) if p else b"")
V=lambda f,q,a:Ether()/IP(src="10.0.0.80",dst=S)/TCP(sport=80,dport=55700,flags=f,seq=q,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
