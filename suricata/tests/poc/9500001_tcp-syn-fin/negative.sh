#!/usr/bin/env bash
# Negative SID 9500001: a normal SYN (only S set) to_server -> exercises the same
# decisive surface (TCP flags inspection) but is a LEGAL combo -> MUST stay silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP
p=Ether()/IP(src="10.0.0.70",dst="10.0.0.80")/TCP(sport=50000,dport=443,flags="S",seq=1)
p.time=1_700_000_000.0
wrpcap(sys.argv[1],[p])
PY
