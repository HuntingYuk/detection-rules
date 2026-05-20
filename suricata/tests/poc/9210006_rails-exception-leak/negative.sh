#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# Exercises fast_pattern (the phrase IS present) but as docs prose with no
# Rails-frame markers (no <h2>/extracted source/app\/ path/Rails.root/RAILS_ENV)
# -> pcre rejects -> silent (§19 T6).
body=(b"<html><body><p>The page titled 'Action Controller: Exception caught' appears "
      b"when a Rails app raises an unhandled exception in development mode; disable it "
      b"before deploying to production by setting config.consider_all_requests_local = false.</p></body></html>")
reqh=b"GET /help/rails-errors HTTP/1.1\r\nHost: docs.example\r\nConnection: close\r\n\r\n"
resp=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.113";D="10.0.0.80";SP=51112
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=SP,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a,p=b"":Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=SP,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
cs,ss=1000,2000
pk=[C("S",cs,0),V("SA",ss,cs+1),C("A",cs+1,ss+1)]; cs+=1; ss+=1
pk+=[C("PA",cs,ss,reqh)]; cs+=len(reqh); pk+=[V("A",ss,cs)]
pk+=[V("PA",ss,cs,resp)]; ss+=len(resp); pk+=[C("A",cs,ss)]
t=1_700_000_000.0
for i,p in enumerate(pk): p.time=t+i*0.01
wrpcap(sys.argv[1],pk)
PY
