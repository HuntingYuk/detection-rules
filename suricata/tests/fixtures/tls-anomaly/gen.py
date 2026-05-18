#!/usr/bin/env python3
# Golden TLS fixture generator (spec §19 T3). Hand-crafts a valid TLS 1.2
# ClientHello (no scapy-TLS; deterministic, no root) wrapped in a TCP handshake.
# mal.pcap   : SNI = bare IP literal  (attacker-shaped -> rule must fire)
# benign.pcap: SNI = normal hostname  (exercises tls.sni -> rule must stay silent)
import os, struct, sys
from scapy.all import wrpcap, Ether, IP, TCP, Raw
HERE=os.path.dirname(os.path.abspath(__file__))

def client_hello(sni: bytes) -> bytes:
    server_name = b"\x00" + struct.pack(">H", len(sni)) + sni            # type host_name
    sni_list    = struct.pack(">H", len(server_name)) + server_name
    sni_ext     = b"\x00\x00" + struct.pack(">H", len(sni_list)) + sni_list
    other_ext   = bytes.fromhex("000a00040002001700170000000d0004000204030016000000170000")
    exts        = sni_ext + other_ext
    ciphers     = bytes.fromhex("130113021303c02fc02bc030c014009c")
    body = (b"\x03\x03" + b"\x11"*32 + b"\x00"
            + struct.pack(">H", len(ciphers)) + ciphers
            + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    hs  = b"\x01" + struct.pack(">I", len(body))[1:] + body              # handshake msg
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs             # TLS record

def pcap(path, sni, src):
    rec = client_hello(sni); D = "10.0.0.80"
    C = lambda f,s,a,p=b"": Ether()/IP(src=src,dst=D)/TCP(sport=44460,dport=443,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
    V = lambda f,s,a,p=b"": Ether()/IP(src=D,dst=src)/TCP(sport=443,dport=44460,flags=f,seq=s,ack=a)/(Raw(p) if p else b"")
    pk=[C("S",1000,0),V("SA",2000,1001),C("A",1001,2001),C("PA",1001,2001,rec),V("A",2001,1001+len(rec))]
    t=1_700_000_000.0
    for i,p in enumerate(pk): p.time=t+i*0.01
    wrpcap(path, pk)

pcap(os.path.join(HERE,"mal.pcap"),    b"203.0.113.45",        "10.0.0.9")
pcap(os.path.join(HERE,"benign.pcap"), b"cdn.assets.example.com","10.0.0.60")
print("wrote mal.pcap (SNI=bare IP) + benign.pcap (SNI=hostname)")
