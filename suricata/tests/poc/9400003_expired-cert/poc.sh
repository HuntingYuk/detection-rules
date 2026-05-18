#!/usr/bin/env bash
# PoC SID 9400003. FIXTURE-REPLAY: real TLS1.2 handshake (MemoryBIO-captured) whose
# server Certificate is an expired self-signed cert (notAfter=2000). Provenance:
# tests/fixtures/tls-anomaly/gen.py (needs OpenSSL 3).
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/certmal.pcap" "$OUT"
