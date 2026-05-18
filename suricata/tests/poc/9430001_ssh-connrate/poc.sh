#!/usr/bin/env bash
# PoC for SID 9430001 (SSH brute by connection rate). Threshold PoC: 25 SYN to
# tcp/22 from ONE src within 60s -> trips threshold count 20/60s -> fires.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
SRC="10.0.0.99"; DST="10.0.0.22"
pkts=[]; t=1_700_000_000.0
for i in range(25):
    p=Ether()/IP(src=SRC,dst=DST)/TCP(sport=40000+i,dport=22,flags="S",seq=1000+i)
    p.time=t; t+=1.0            # 25 over 25s, inside the 60s window
    pkts.append(p)
wrpcap(sys.argv[1], pkts)
PY
