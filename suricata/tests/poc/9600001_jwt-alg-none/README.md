# PoC — SID 9600001 (jwt-alg-none)

- Rule file: `rules/plaintext/misc.rules`
- Expected: `poc.sh` fires SID `9600001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
