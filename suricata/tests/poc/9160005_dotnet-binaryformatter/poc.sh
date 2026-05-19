#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# __VIEWSTATE carrying a base64 .NET BinaryFormatter stream (magic AAEAAAD/////).
blob=b"AAEAAAD/////AQAAAAAAAAAMAgAAAFhTeXN0ZW0uRGF0YS5TZXJ2aWNlc2dhZGdldA=="
body=b"__VIEWSTATE="+blob
req=b"POST /page.aspx HTTP/1.1\r\nHost: app.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.37";D="10.0.0.80"
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=44509,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=44509,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
