# PoC — SID 9150002 (url-scheme-smuggling)

- Rule file: `rules/plaintext/ssrf.rules`
- Expected: `poc.sh` fires SID `9150002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
