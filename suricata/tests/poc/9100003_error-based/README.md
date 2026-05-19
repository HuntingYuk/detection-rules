# PoC — SID 9100003 (error-based)

- Rule file: `rules/plaintext/sqli.rules`
- Expected: `poc.sh` fires SID `9100003`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
