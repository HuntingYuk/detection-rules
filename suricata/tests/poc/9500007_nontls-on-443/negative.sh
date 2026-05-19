#!/usr/bin/env bash
# Negative SID 9500007: a real TLS ClientHello to :443 -> app-layer=tls -> the
# app-layer-protocol:!tls decisive check fails -> silent. Reuses the committed
# tls-anomaly benign fixture (ClientHello, dport 443).
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/benign.pcap" "$OUT"
