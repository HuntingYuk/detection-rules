#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# one SYN-with-data (decisive condition once) + a normal dataless SYN -> below 3/60 -> silent
pkts=[Ether()/IP(src="10.0.0.71",dst="10.0.0.80")/TCP(sport=51010,dport=80,flags="S",seq=1)/Raw(b"TFO"),
      Ether()/IP(src="10.0.0.71",dst="10.0.0.80")/TCP(sport=51011,dport=80,flags="S",seq=1)]
t=1_700_000_000.0
for p in pkts: p.time=t; t+=2.0
wrpcap(sys.argv[1],pkts)
PY
