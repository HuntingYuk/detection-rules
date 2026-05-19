# PoC — SID 9110002 (event-handler)

- Rule file: `rules/plaintext/xss.rules`
- Expected: `poc.sh` fires SID `9110002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
