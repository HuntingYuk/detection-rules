#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, UDP
pkts=[]; t=1_700_000_000.0
for i in range(6):
    p=Ether()/IP(src="10.0.0.70",dst="10.0.0.53")/UDP(sport=51000+i,dport=53)
    p.time=t; t+=1.0; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
