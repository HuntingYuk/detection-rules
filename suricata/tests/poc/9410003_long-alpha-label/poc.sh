#!/usr/bin/env bash
# PoC SID 9410003: 18 DNS queries/one src, each with a 52-char all-lowercase-alpha
# single label -> trips detection_filter 15/60s.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys, string
from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR
SRC="10.0.0.93"
base=(string.ascii_lowercase*3)[:52]   # 52 a-z chars
pkts=[]; t=1_700_000_000.0
for i in range(18):
    qn=f"{base}.tun{i:02d}.example"
    p=Ether()/IP(src=SRC,dst="10.0.0.53")/UDP(sport=40000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=qn))
    p.time=t; t+=0.3; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
