#!/usr/bin/env bash
# PoC for SID 9420001 (TCP SYN port-scan). Threshold PoC (spec §19 T2): 70 bare-SYN
# packets from ONE src to many dports within the 10s window -> trips threshold
# count 60/10s -> fires. Deterministic, no server, no root.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
SRC="10.0.0.66"; DST="10.0.0.80"
pkts=[]; t=1_700_000_000.0
for i in range(70):
    p=Ether()/IP(src=SRC,dst=DST)/TCP(sport=40000+i,dport=1+i,flags="S",seq=1000+i)
    p.time=t; t+=0.05            # 70 pkts over ~3.5s, well inside 10s
    pkts.append(p)
wrpcap(sys.argv[1], pkts)
PY
