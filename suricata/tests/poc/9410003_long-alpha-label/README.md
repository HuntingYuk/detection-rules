# PoC — SID 9410003 (long-alpha-label)

- Rule file: `rules/tls-meta/dns-tunnel.rules`
- Expected: `poc.sh` fires SID `9410003`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
