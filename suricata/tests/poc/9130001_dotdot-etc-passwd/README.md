# PoC — SID 9130001 (dotdot-etc-passwd)

- Rule file: `rules/plaintext/traversal.rules`
- Expected: `poc.sh` fires SID `9130001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
