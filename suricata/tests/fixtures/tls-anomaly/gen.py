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

# 9400003 (expired server cert): real OpenSSL3 self-signed certs (expired vs valid)
# + an in-process MemoryBIO TLS1.2 handshake -> the Certificate message is real and
# Suricata-parseable. Needs OpenSSL 3 (Apple LibreSSL lacks -not_after). Deterministic
# w.r.t. the rule (tls_cert_expired depends only on notAfter, fixed at 2000).
def _cert_pcaps():
    import subprocess, tempfile, ssl
    OSSL=next((o for o in ("/opt/homebrew/bin/openssl","/opt/homebrew/opt/openssl@3/bin/openssl")
               if os.path.exists(o)), "openssl")
    td=tempfile.mkdtemp()
    def mkcert(cn, args):
        c=os.path.join(td,cn+".pem"); k=os.path.join(td,cn+".key")
        subprocess.run([OSSL,"req","-x509","-newkey","rsa:2048","-keyout",k,"-out",c,
            "-nodes","-subj","/CN=%s/O=HuntingyukLab"%cn]+args,check=True,
            capture_output=True)
        return c,k
    ec,ek=mkcert("evil-selfsigned.example",
                 ["-not_before","20000101000000Z","-not_after","20000102000000Z"])
    vc,vk=mkcert("ok-selfsigned.example",["-days","3650"])
    def hs(cert,key,host):
        sc=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); sc.minimum_version=sc.maximum_version=ssl.TLSVersion.TLSv1_2; sc.load_cert_chain(cert,key)
        cc=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); cc.check_hostname=False; cc.verify_mode=ssl.CERT_NONE
        cc.minimum_version=cc.maximum_version=ssl.TLSVersion.TLSv1_2
        ci,co,si,so=ssl.MemoryBIO(),ssl.MemoryBIO(),ssl.MemoryBIO(),ssl.MemoryBIO()
        cl=cc.wrap_bio(ci,co,server_hostname=host); sv=sc.wrap_bio(si,so,server_side=True)
        rec=[]; cdone=sdone=False
        for _ in range(40):
            for o,which in ((cl,'c'),(sv,'s')):
                try:
                    o.do_handshake()
                    if which=='c': cdone=True
                    else: sdone=True
                except (ssl.SSLWantReadError,ssl.SSLWantWriteError): pass
            d=co.read()
            if d: si.write(d); rec.append(('c2s',d))
            d=so.read()
            if d: ci.write(d); rec.append(('s2c',d))
            if cdone and sdone: break
        return rec
    def build(rec,name,csrc):
        # Emit segments in RECORDED (handshake-interleaved) order with per-chunk
        # seq/ack. Suricata's TLS state machine needs the cross-direction handshake
        # ordering preserved (ClientHello -> ServerHello+Certificate -> ...), so do
        # NOT concatenate per direction (that desyncs the parser; cert won't parse).
        D="10.0.0.80"; cseq=1000; sseq=2000; pk=[]
        mk=lambda s,d,sp,dp,fl,sq,ak,pl=b"": Ether()/IP(src=s,dst=d)/TCP(sport=sp,dport=dp,flags=fl,seq=sq,ack=ak)/(Raw(pl) if pl else b"")
        pk+=[mk(csrc,D,44470,443,"S",cseq,0), mk(D,csrc,443,44470,"SA",sseq,cseq+1)]
        cseq+=1; pk+=[mk(csrc,D,44470,443,"A",cseq,sseq+1)]; sseq+=1
        for direction,data in rec:
            if direction=='c2s':
                pk.append(mk(csrc,D,44470,443,"PA",cseq,sseq,data)); cseq+=len(data)
                pk.append(mk(D,csrc,443,44470,"A",sseq,cseq))
            else:
                pk.append(mk(D,csrc,443,44470,"PA",sseq,cseq,data)); sseq+=len(data)
                pk.append(mk(csrc,D,44470,443,"A",cseq,sseq))
        t=1_700_000_000.0
        for i,p in enumerate(pk): p.time=t+i*0.01
        wrpcap(os.path.join(HERE,name),pk)
    build(hs(ec,ek,"evil-selfsigned.example"),"certmal.pcap","10.0.0.13")
    build(hs(vc,vk,"ok-selfsigned.example"),"certbenign.pcap","10.0.0.63")

try:
    _cert_pcaps()
    print("wrote mal/benign/ja3mal/ja3benign/certmal/certbenign .pcap")
except Exception as e:
    print("wrote mal/benign/ja3mal/ja3benign .pcap ; certmal/certbenign SKIPPED:", e)
