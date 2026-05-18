#!/usr/bin/env bash
# Negative for SID 9100001 (threshold rule). Decisive-condition negative per spec
# §19 T2: ONE benign request whose URI literally contains "union select" (a user
# searching) — it DOES hit the fast_pattern AND the pcre, so it exercises the full
# match path, but detection_filter count 3/60s means a single occurrence MUST NOT
# alert. This is exactly the FP the rule is designed to tolerate.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
SRC="10.0.0.50"; DST="10.0.0.80"
uri=b"/search?q=union%20select%20box%20dimensions%20for%20shelving"
req=(b"GET "+uri+b" HTTP/1.1\r\nHost: shop.example\r\n"
     b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n")
def C(fl,seq,ack,pl=b""):
    return Ether()/IP(src=SRC,dst=DST)/TCP(sport=51000,dport=80,flags=fl,seq=seq,ack=ack)/(Raw(pl) if pl else b"")
def S(fl,seq,ack,pl=b""):
    return Ether()/IP(src=DST,dst=SRC)/TCP(sport=80,dport=51000,flags=fl,seq=seq,ack=ack)/(Raw(pl) if pl else b"")
pkts=[C("S",1000,0),S("SA",2000,1001),C("A",1001,2001),
      C("PA",1001,2001,req),S("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pkts: p.time=t; t+=0.01
wrpcap(sys.argv[1], pkts)
PY
