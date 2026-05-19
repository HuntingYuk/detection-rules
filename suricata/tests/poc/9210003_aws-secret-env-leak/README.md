# PoC — SID 9210003 (aws-secret-env-leak)

- Rule file: `rules/plaintext/info-leak.rules`
- Expected: `poc.sh` fires SID `9210003`; `negative.sh` does NOT (but DOES hit the fast_pattern `AWS_SECRET_ACCESS_KEY`).
- Technique: RESPONSE-side — an exposed `.env` / config dump served back over HTTP leaking `AWS_SECRET_ACCESS_KEY=<secret>`. Response-side category (`flow:to_client`), where ET Open is weak. Distinct from the AWS key-id (9210001) and PEM private-key (9210002) response leaks.
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event (response-side; uses the `http_exchange` handshake+request+response pcap shape).
