# PoC — SID 9210002 (private-key-in-response)

- Rule file: `rules/plaintext/info-leak.rules`
- Expected: `poc.sh` fires SID `9210002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
