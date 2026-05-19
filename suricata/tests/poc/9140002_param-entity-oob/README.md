# PoC — SID 9140002 (param-entity-oob)

- Rule file: `rules/plaintext/xxe.rules`
- Expected: `poc.sh` fires SID `9140002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
