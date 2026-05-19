#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
uri=b"/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%29%29%7D/"
req=b"GET "+uri+b" HTTP/1.1\r\nHost: confluence.example\r\nConnection: close\r\n\r\n"
S="10.0.0.45"
C=lambda f,q,a,p=b"":Ether()/IP(src=S,dst="10.0.0.80")/TCP(sport=47200,dport=80,flags=f,seq=q,ack=a)/(Raw(p) if p else b"")
V=lambda f,q,a:Ether()/IP(src="10.0.0.80",dst=S)/TCP(sport=80,dport=47200,flags=f,seq=q,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
