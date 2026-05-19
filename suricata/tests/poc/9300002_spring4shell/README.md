# PoC — SID 9300002 (spring4shell)

- Rule file: `rules/plaintext/known-cve.rules`
- Expected: `poc.sh` fires SID `9300002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
