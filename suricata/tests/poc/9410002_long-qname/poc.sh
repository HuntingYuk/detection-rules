#!/usr/bin/env bash
# PoC SID 9410002: 12 DNS queries/one src with a ~130-char total qname -> trips
# threshold 10/60s. Deterministic.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, UDP, DNS, DNSQR
SRC="10.0.0.91"
lbl=("abcdef12."*15)            # 8*15=120 + parent => >100
pkts=[]; t=1_700_000_000.0
for i in range(12):
    qn=f"{lbl}c{i:02d}.tunnel.example"
    p=Ether()/IP(src=SRC,dst="10.0.0.53")/UDP(sport=40000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=qn))
    p.time=t; t+=0.3; pkts.append(p)
wrpcap(sys.argv[1], pkts)
PY
