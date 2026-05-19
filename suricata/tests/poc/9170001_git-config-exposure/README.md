# PoC — SID 9170001 (git-config-exposure)

- Rule file: `rules/plaintext/access-control.rules`
- Expected: `poc.sh` fires SID `9170001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
