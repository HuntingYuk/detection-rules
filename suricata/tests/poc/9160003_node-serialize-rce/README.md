# PoC — SID 9160003 (node-serialize-rce)

- Rule file: `rules/plaintext/deserialization.rules`
- Expected: `poc.sh` fires SID `9160003`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
