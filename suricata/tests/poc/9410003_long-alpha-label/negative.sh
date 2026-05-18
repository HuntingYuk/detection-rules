#!/usr/bin/env bash
# Negative SID 9410003: normal queries + ONE 30-char alpha label (below the 45-char
# pcre bar) -> decisive condition not reached -> silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR
SRC="10.0.0.62"
qs=["www.example.com","mail.example.org","cdn.assets.example.net",
    "abcdefghijklmnopqrstuvwxyzabcd.short.example"]   # 30-char label < 45
pkts=[]; t=1_700_000_000.0
for i,qn in enumerate(qs):
    p=Ether()/IP(src=SRC,dst="10.0.0.53")/UDP(sport=42000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=qn))
    p.time=t; t+=1.0; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
