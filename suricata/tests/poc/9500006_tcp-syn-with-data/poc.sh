#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
pkts=[]; t=1_700_000_000.0
for i in range(4):
    p=Ether()/IP(src="10.0.0.66",dst="10.0.0.80")/TCP(sport=44450+i,dport=80,flags="S",seq=1)/Raw(b"EVILDATA")
    p.time=t; t+=0.5; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
