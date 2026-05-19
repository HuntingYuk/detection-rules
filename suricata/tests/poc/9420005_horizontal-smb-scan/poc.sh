#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
pkts=[]; t=1_700_000_000.0
for i in range(40):
    p=Ether()/IP(src="10.0.0.66",dst="10.1.%d.%d"%(i//254,1+i%254))/TCP(sport=40000+i,dport=445,flags="S",seq=1+i)
    p.time=t; t+=0.3; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
