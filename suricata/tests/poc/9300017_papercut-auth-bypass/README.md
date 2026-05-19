# PoC — SID 9300017 (papercut-auth-bypass)

- Rule file: `rules/plaintext/known-cve.rules`
- Expected: `poc.sh` fires SID `9300017`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
