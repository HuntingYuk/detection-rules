# PoC — SID 9400002 (tls-anomaly: client JA3 on curated bad-list)

- Rule: `rules/tls-meta/tls-anomaly.rules` · network_mode `tls-meta`
- Type: **dataset + fixture-replay** (spec §19 T2(d)+T3).
- Dataset: `rules/datasets/badja3.lst` (Suricata `type string`, base64 JA3 md5),
  wired via `datasets: badja3:` in the gate yaml. Provenance/TTL in the file header.
- Fixtures: `tests/fixtures/tls-anomaly/{ja3mal,ja3benign}.pcap` (gen.py).
  ja3mal JA3 = 8ac245d5438d504fc1947376190c723a (bad-listed) →fires 9400002.
  ja3benign JA3 = af1db45e728de3b5699758484a36aca8 (not listed) →silent.
- Suricata gate version: **8.0.4** (ja3-fingerprints: yes). Confirm prod major.
- Prod note: production suricata.yaml MUST define `datasets: badja3:` (same as gate).
