# PoC — SID 9190001 (php-eval-post)

- Rule file: `rules/plaintext/webshell.rules`
- Expected: `poc.sh` fires SID `9190001`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
