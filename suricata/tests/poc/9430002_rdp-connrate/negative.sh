#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
# Below threshold (3 SYNs to 3389) -> silent.
S="10.0.0.120";D="10.0.0.80";pkts=[];t=1_700_000_000.0
for i in range(3):
    p=Ether()/IP(src=S,dst=D)/TCP(sport=51200+i,dport=3389,flags="S",seq=1000+i)
    p.time=t;t+=0.5
    pkts.append(p)
wrpcap(sys.argv[1],pkts)
PY
