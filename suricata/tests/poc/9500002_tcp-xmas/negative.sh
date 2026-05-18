#!/usr/bin/env bash
# Negative SID 9500002: normal PSH-ACK data segment (PSH set, but with ACK = legal)
# -> exercises TCP-flags inspection but is a legitimate combo -> MUST stay silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
p=Ether()/IP(src="10.0.0.70",dst="10.0.0.80")/TCP(sport=50001,dport=80,flags="PA",seq=1,ack=1)/Raw(b"hello")
p.time=1_700_000_000.0
wrpcap(sys.argv[1],[p])
PY
