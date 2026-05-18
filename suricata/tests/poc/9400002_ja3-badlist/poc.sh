#!/usr/bin/env bash
# PoC SID 9400002. FIXTURE-REPLAY: golden TLS pcap whose ClientHello JA3 ==
# the curated bad-list entry (SNI is a hostname, so it does NOT also trip 9400001).
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/ja3mal.pcap" "$OUT"
