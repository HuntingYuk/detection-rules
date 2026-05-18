# PoC — SID 9420002 (icmp-sweep)

- Rule file: `rules/tls-meta/l34-recon.rules`
- Expected: `poc.sh` fires SID `9420002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
