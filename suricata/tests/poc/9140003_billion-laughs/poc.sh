#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
body=(b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
      b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
      b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>')
req=b"POST /xml HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/xml\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.67"
C=lambda f,q,a,p=b"":Ether()/IP(src=S,dst="10.0.0.80")/TCP(sport=49400,dport=80,flags=f,seq=q,ack=a)/(Raw(p) if p else b"")
V=lambda f,q,a:Ether()/IP(src="10.0.0.80",dst=S)/TCP(sport=80,dport=49400,flags=f,seq=q,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
