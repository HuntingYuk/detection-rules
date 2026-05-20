#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
# Threshold 30/60s by_src EXCEEDS — send 31 SYNs to tcp/3389 from one src.
S="10.0.0.70";D="10.0.0.80";pkts=[];t=1_700_000_000.0
for i in range(31):
    p=Ether()/IP(src=S,dst=D)/TCP(sport=44800+i,dport=3389,flags="S",seq=1000+i)
    p.time=t;t+=0.05
    pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
