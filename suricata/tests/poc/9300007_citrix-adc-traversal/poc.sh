#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
req=b"POST /vpn/../vpns/portal/scripts/newbm.pl HTTP/1.1\r\nHost: citrix.example\r\nNSC_USER: ../../../netscaler/portal/templates/x\r\nNSC_NONCE: c\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\nConnection: close\r\n\r\nurl=x"
S="10.0.0.49"
C=lambda f,q,a,p=b"":Ether()/IP(src=S,dst="10.0.0.80")/TCP(sport=47600,dport=80,flags=f,seq=q,ack=a)/(Raw(p) if p else b"")
V=lambda f,q,a:Ether()/IP(src="10.0.0.80",dst=S)/TCP(sport=80,dport=47600,flags=f,seq=q,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
