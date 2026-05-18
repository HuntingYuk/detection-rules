# PoC — SID 9400003 (tls-anomaly: expired server certificate)

- Rule: `rules/tls-meta/tls-anomaly.rules` · network_mode `tls-meta`
- Keyword: `tls_cert_expired` (Suricata legacy-name; `tls.cert_expired` is NOT
  valid on 8.0.4 — verified via `suricata --list-keywords`).
- Type: fixture-replay. Fixtures `tests/fixtures/tls-anomaly/{certmal,certbenign}.pcap`
  built by gen.py: OpenSSL 3 self-signed certs (expired notAfter=2000 vs valid)
  + in-process MemoryBIO TLS1.2 handshake -> real, Suricata-parseable Certificate.
- certmal → fires 9400003; certbenign (valid cert) → silent.
- Suricata gate version: 8.0.4. Note: generic *self-signed* detection is NOT a
  clean network signature (Suricata can't compare cert_subject vs cert_issuer in a
  rule) — deliberately scoped to *expired*, like A04/IDOR were scoped out.
