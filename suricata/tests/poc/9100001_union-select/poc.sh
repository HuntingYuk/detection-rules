#!/usr/bin/env bash
# PoC for SID 9100001 (canonical UNION SQLi, MEDIUM, threshold rule).
# Threshold PoC type (spec §19 T2): detection_filter needs count 3 / 60s / by_src,
# so we send 4 matching requests from ONE source IP in separate flows. The 3rd+
# match fires the rule. Deterministic, no server, no root.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
SRC="10.0.0.9"; DST="10.0.0.80"
uri=b"/item?id=1%20union%20select%20username,password%20from%20users--%20-"
req=(b"GET "+uri+b" HTTP/1.1\r\nHost: victim.example\r\n"
     b"User-Agent: sqlmap/1.x\r\nAccept: */*\r\nConnection: close\r\n\r\n")
pkts=[]; t=1_700_000_000.0
for i in range(4):                      # 4 matches > count 3 -> alert
    sp=44440+i
    def C(fl,seq,ack,pl=b"",sp=sp):
        return Ether()/IP(src=SRC,dst=DST)/TCP(sport=sp,dport=80,flags=fl,seq=seq,ack=ack)/(Raw(pl) if pl else b"")
    def S(fl,seq,ack,pl=b"",sp=sp):
        return Ether()/IP(src=DST,dst=SRC)/TCP(sport=80,dport=sp,flags=fl,seq=seq,ack=ack)/(Raw(pl) if pl else b"")
    flow=[C("S",1000,0),S("SA",2000,1001),C("A",1001,2001),
          C("PA",1001,2001,req),S("A",2001,1001+len(req))]
    for p in flow: p.time=t; t+=0.01
    pkts+=flow
wrpcap(sys.argv[1], pkts)
PY
