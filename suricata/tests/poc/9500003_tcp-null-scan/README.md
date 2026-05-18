# PoC — SID 9500003 (tcp-null-scan)

- Rule file: `rules/tls-meta/protocol-anomaly.rules`
- Expected: `poc.sh` fires SID `9500003`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
