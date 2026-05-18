# PoC — SID 9400001 (tls-anomaly: SNI is a bare IPv4 literal)

- Rule: `rules/tls-meta/tls-anomaly.rules` · network_mode `tls-meta`
- Type: **fixture-replay** (golden TLS pcap; scapy cannot deterministically
  produce a parseable handshake — spec §19 T3).
- Fixtures: `tests/fixtures/tls-anomaly/{mal,benign}.pcap`
  provenance `tests/fixtures/tls-anomaly/gen.py` (hand-crafted raw TLS1.2
  ClientHello, deterministic, no root).
- mal: SNI=`203.0.113.45` → fires 9400001. benign: SNI=`cdn.assets.example.com`
  → reaches the tls.sni pcre, fails the IP regex → silent.
- Suricata gate version (first green): **8.0.4 RELEASE** (local). Confirm prod major.
