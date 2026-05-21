#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# Strengthened negative: carries the fast_pattern literal (via decoded http.uri)
# BUT the rule's pcre rejects the surrounding context (§19 T6 ideal).

uri=b'/env/status?topic=/.env+config+file+location+overview'
hdrs=b''
S="10.0.0.151";D="10.0.0.80";SP=53029
S_LIT="10.0.0.80"
def _flow(sport_local):
    req=b"GET "+uri+b" HTTP/1.1\r\nHost: docs.example\r\n"+hdrs+b"Connection: close\r\n\r\n"
    C=lambda f,s,a,p=b"",sp=sport_local: Ether()/IP(src=S,dst=D)/TCP(sport=sp,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
    V=lambda f,s,a,sp=sport_local: Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=sp,flags=f,seq=s,ack=a)
    return [C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
pk=_flow(53029)
t=1_700_000_000.0
for i,p in enumerate(pk): p.time=t+i*0.01
wrpcap(sys.argv[1],pk)
PY
