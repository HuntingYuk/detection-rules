#!/usr/bin/env bash
# Negative for SID 9430001. Decisive-condition negative: 5 SYN to tcp/22 from ONE
# src (a normal admin opening a couple of SSH sessions) — this IS the traffic the
# rule keys on, but 5 << threshold 20/60s -> MUST stay silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
SRC="10.0.0.40"; DST="10.0.0.22"
pkts=[]; t=1_700_000_000.0
for i in range(5):
    p=Ether()/IP(src=SRC,dst=DST)/TCP(sport=52000+i,dport=22,flags="S",seq=1000+i)
    p.time=t; t+=2.0
    pkts.append(p)
wrpcap(sys.argv[1], pkts)
PY
