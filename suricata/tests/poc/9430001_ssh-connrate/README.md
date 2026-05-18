# PoC — SID 9430001 (ssh-connrate)

- Rule file: `rules/tls-meta/infra-bruteforce.rules`
- Expected: `poc.sh` fires SID `9430001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
