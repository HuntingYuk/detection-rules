#!/usr/bin/env bash
# Negative for SID 9420001. Decisive-condition negative (spec §19 T2/T6): 10 bare
# SYNs from ONE src (normal client opening a few connections) — this IS exactly the
# traffic the rule keys on (SYN, to_server) so the decisive condition is exercised,
# but 10 << threshold 60/10s -> MUST stay silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
SRC="10.0.0.70"; DST="10.0.0.80"
pkts=[]; t=1_700_000_000.0
for i in range(10):
    p=Ether()/IP(src=SRC,dst=DST)/TCP(sport=50000+i,dport=443,flags="S",seq=1000+i)
    p.time=t; t+=0.3
    pkts.append(p)
wrpcap(sys.argv[1], pkts)
PY
