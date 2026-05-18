#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, UDP
pkts=[]; t=1_700_000_000.0
for i in range(60):
    p=Ether()/IP(src="10.0.0.66",dst="10.0.0.80")/UDP(sport=40000+i,dport=1+i)
    p.time=t; t+=0.05; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
