# PoC — SID 9410001 (dns-tunnel: long high-entropy hex label)

- Rule file: `rules/tls-meta/dns-tunnel.rules`  ·  network_mode: `any`
- Type: **threshold + fixture-replay** (spec §19 T2 + T3, UC3 family pool).
- Fixtures (committed, shared family pool):
  `tests/fixtures/dns-tunnel/{poc.pcap,benign.pcap}` — provenance:
  `tests/fixtures/dns-tunnel/gen.py` (deterministic, re-runnable).
- Expected:
  - `poc.sh` → replays 20 long-hex-label DNS queries from one src → trips
    `detection_filter count 15/60s` → **SID 9410001 fires**.
  - `negative.sh` → benign queries + ONE 50-hex label that **matches the pcre**
    (decisive condition exercised) but is below the volume threshold → **silent**.
- Non-payload rule: NO fast_pattern by design (spec §22 C1) — the decisive
  condition is the bounded `dns.query` pcre, and the negative exercises THAT.
- Suricata gate version (first green): **8.0.4 RELEASE** (local brew).
  Production Suricata major version still to be confirmed before mass lock-in.
