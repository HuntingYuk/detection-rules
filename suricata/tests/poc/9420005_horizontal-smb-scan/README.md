# PoC — SID 9420005 (horizontal-smb-scan)

- Rule file: `rules/tls-meta/l34-recon.rules`
- Expected: `poc.sh` fires SID `9420005`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
