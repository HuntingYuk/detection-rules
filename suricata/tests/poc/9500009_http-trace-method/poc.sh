#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
req=b"TRACE / HTTP/1.1\r\nHost: victim.example\r\nConnection: close\r\n\r\n"
SRC="10.0.0.78"; D="10.0.0.80"; pkts=[]; t=1_700_000_000.0
for i in range(3):
    sp=46000+i
    C=lambda f,s,a,p=b"",sp=sp:Ether()/IP(src=SRC,dst=D)/TCP(sport=sp,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
    V=lambda f,s,a,sp=sp:Ether()/IP(src=D,dst=SRC)/TCP(sport=80,dport=sp,flags=f,seq=s,ack=a)
    fl=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
    for p in fl: p.time=t; t+=0.01
    pkts+=fl
wrpcap(sys.argv[1],pkts)
PY
