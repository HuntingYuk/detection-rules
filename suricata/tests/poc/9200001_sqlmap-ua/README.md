# PoC — SID 9200001 (sqlmap-ua)

- Rule file: `rules/plaintext/recon-http.rules`
- Expected: `poc.sh` fires SID `9200001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
