# PoC — SID 9150003 (gcp-metadata-host)

- Rule file: `rules/plaintext/ssrf.rules`
- Expected: `poc.sh` fires SID `9150003`; `negative.sh` does NOT (but DOES hit the fast_pattern `metadata.google.internal`).
- Technique: SSRF to the GCP instance metadata service via its hostname (`http://metadata.google.internal/computeMetadata/v1/...`). The bare-IP form is 9150001; the dangerous-scheme form is 9150002 — this covers the hostname GAP.
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event.
