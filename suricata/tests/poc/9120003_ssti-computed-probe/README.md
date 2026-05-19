# PoC — SID 9120003 (ssti-computed-probe)

- Rule file: `rules/plaintext/cmdi.rules`
- Expected: `poc.sh` fires SID `9120003`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
