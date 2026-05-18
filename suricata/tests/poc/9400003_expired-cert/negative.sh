#!/usr/bin/env bash
# Negative SID 9400003. Decisive-condition negative: same handshake/cert-parse path
# but a VALID self-signed cert -> tls_cert_expired false -> silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/certbenign.pcap" "$OUT"
