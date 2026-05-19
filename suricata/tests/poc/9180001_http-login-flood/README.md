# PoC — SID 9180001 (http-login-flood)

- Rule file: `rules/plaintext/auth-bruteforce.rules`
- Expected: `poc.sh` fires SID `9180001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
