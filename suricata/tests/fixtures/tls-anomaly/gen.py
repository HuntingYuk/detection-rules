#!/usr/bin/env python3
# Golden TLS fixture generator (spec §19 T3). Hand-crafted TLS1.2 ClientHello
# (no scapy-TLS; deterministic, no root) in a TCP handshake. The cipher list drives
# the JA3; the SNI value does NOT (JA3 uses extension *types*, not the SNI string).
import os, struct
from scapy.all import wrpcap, Ether, IP, TCP, Raw
HERE=os.path.dirname(os.path.abspath(__file__))
DFLT=bytes.fromhex("130113021303c02fc02bc030c014009c")          # -> JA3 8ac245...
ALT =bytes.fromhex("c02cc030009f00390033c013")                  # different -> other JA3

def client_hello(sni: bytes, ciphers: bytes) -> bytes:
    sn = b"\x00"+struct.pack(">H",len(sni))+sni
    snl= struct.pack(">H",len(sn))+sn
    sni_ext=b"\x00\x00"+struct.pack(">H",len(snl))+snl
    other=bytes.fromhex("000a00040002001700170000000d0004000204030016000000170000")
    exts=sni_ext+other
    body=(b"\x03\x03"+b"\x11"*32+b"\x00"+struct.pack(">H",len(ciphers))+ciphers
          +b"\x01\x00"+struct.pack(">H",len(exts))+exts)
    hs=b"\x01"+struct.pack(">I",len(body))[1:]+body
    return b"\x16\x03\x01"+struct.pack(">H",len(hs))+hs

def pcap(name, sni, ciphers, src):
    rec=client_hello(sni,ciphers); D="10.0.0.80"
    C=lambda f,s,a,p=b"": Ether()/IP(src=src,dst=D)/TCP(sport=44460,dport=443,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
    V=lambda f,s,a,p=b"": Ether()/IP(src=D,dst=src)/TCP(sport=443,dport=44460,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
    pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,rec),V("A",2001,1001+len(rec))]
    t=1_700_000_000.0
    for i,p in enumerate(pk): p.time=t+i*0.01
    wrpcap(os.path.join(HERE,name),pk)

# 9400001 (SNI bare-IP):
pcap("mal.pcap",    b"203.0.113.45",          DFLT, "10.0.0.9")
pcap("benign.pcap", b"cdn.assets.example.com",DFLT, "10.0.0.60")
# 9400002 (JA3 bad-list); hostname SNI so it does NOT also trip 9400001:
pcap("ja3mal.pcap",   b"bad.tooling.example", DFLT, "10.0.0.11")   # JA3 == badlisted
pcap("ja3benign.pcap",b"good.client.example", ALT,  "10.0.0.62")   # different JA3
print("wrote mal/benign/ja3mal/ja3benign .pcap")
