#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, ICMP
pkts=[]; t=1_700_000_000.0
for i in range(15):
    p=Ether()/IP(src="10.0.0.66",dst="10.0.0.%d"%(1+i))/ICMP(type=13,id=5,seq=i)
    p.time=t; t+=0.1; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
