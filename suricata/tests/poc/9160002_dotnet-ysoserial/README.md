# PoC — SID 9160002 (dotnet-ysoserial)

- Rule file: `rules/plaintext/deserialization.rules`
- Expected: `poc.sh` fires SID `9160002`; `negative.sh` does NOT (but DOES hit the fast_pattern).
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event | threshold | flowbit | tls-fixture (delete as appropriate).
