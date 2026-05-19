# PoC — SID 9160004 (python-yaml-objinject)

- Rule file: `rules/plaintext/deserialization.rules`
- Expected: `poc.sh` fires SID `9160004`; `negative.sh` does NOT (but DOES hit the fast_pattern `!!python/`).
- Technique: Python object injection via an unsafe `yaml.load` — the `!!python/object/apply:os.system` PyYAML tag drives arbitrary call construction. Distinct from the Java (9160001), .NET (9160002), Node.js (9160003) deserialization variants.
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event.
