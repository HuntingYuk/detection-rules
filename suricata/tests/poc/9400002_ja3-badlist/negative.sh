#!/usr/bin/env bash
# Negative SID 9400002. Decisive-condition negative: a real ClientHello with a
# DIFFERENT JA3 (not on the bad-list) + SNI present -> reaches ja3.hash + dataset
# check, hash not in set -> silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/ja3benign.pcap" "$OUT"
