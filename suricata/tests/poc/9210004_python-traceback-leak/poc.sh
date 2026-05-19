#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
body=(b"Traceback (most recent call last):\n"
      b'  File "/srv/app/views.py", line 87, in get_user\n'
      b"    return User.objects.get(pk=uid)\n"
      b"KeyError: 'uid'\n")
reqh=b"GET /api/user HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"
resp=b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.40";D="10.0.0.80";SP=44512
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=SP,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a,p=b"":Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=SP,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
cs,ss=1000,2000
pk=[C("S",cs,0),V("SA",ss,cs+1),C("A",cs+1,ss+1)]; cs+=1; ss+=1
pk+=[C("PA",cs,ss,reqh)]; cs+=len(reqh); pk+=[V("A",ss,cs)]
pk+=[V("PA",ss,cs,resp)]; ss+=len(resp); pk+=[C("A",cs,ss)]
t=1_700_000_000.0
for i,p in enumerate(pk): p.time=t+i*0.01
wrpcap(sys.argv[1],pk)
PY
