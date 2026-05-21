#!/usr/bin/env bash
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
python3 - "$OUT" <<'PY'
import sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
# Exercises uri.raw fast_pattern (the exploit URL marker IS present, perhaps a
# scanner attempt) but body has NO #post_render array with exec/system gadget
# -> http.request_body pcre rejects -> silent (§19 T6).
body=b"form_id=user_register_form&_drupal_ajax=1&mail=alice@example.com"
uri=b"/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
req=b"POST "+uri+b" HTTP/1.1\r\nHost: drupal.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body
S="10.0.0.122";D="10.0.0.80"
C=lambda f,s,a,p=b"":Ether()/IP(src=S,dst=D)/TCP(sport=51122,dport=80,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
V=lambda f,s,a:Ether()/IP(src=D,dst=S)/TCP(sport=80,dport=51122,flags=f,seq=s,ack=a)
pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,req),V("A",2001,1001+len(req))]
t=1_700_000_000.0
for p in pk:p.time=t;t+=0.01
wrpcap(sys.argv[1],pk)
PY
