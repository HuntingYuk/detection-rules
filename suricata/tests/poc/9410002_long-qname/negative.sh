#!/usr/bin/env bash
# Negative SID 9410002: 5 queries with a ~90-char qname (long-ish but BELOW the
# 100-char pcre bar) from one src -> does not reach the decisive condition -> silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR
SRC="10.0.0.61"
lbl=("abcd1234."*9)             # ~81 + parent => <100
pkts=[]; t=1_700_000_000.0
for i in range(5):
    qn=f"{lbl}cdn.example.net"
    p=Ether()/IP(src=SRC,dst="10.0.0.53")/UDP(sport=41000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=qn))
    p.time=t; t+=1.0; pkts.append(p)
wrpcap(sys.argv[1], pkts)
PY
