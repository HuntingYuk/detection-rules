#!/usr/bin/env bash
# PoC SID 9420002: 40 ICMP echo-requests from ONE src to many dst within 10s ->
# trips threshold 30/10s -> fires.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, ICMP
SRC="10.0.0.66"
pkts=[]; t=1_700_000_000.0
for i in range(40):
    p=Ether()/IP(src=SRC,dst="10.0.0.%d"%(1+i))/ICMP(type=8,id=1,seq=i)
    p.time=t; t+=0.05; pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
