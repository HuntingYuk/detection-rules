#!/usr/bin/env bash
# Negative SID 9400001. Decisive-condition negative: a real ClientHello with a normal
# hostname SNI -> reaches tls.sni + the IP pcre and is rejected there -> silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/benign.pcap" "$OUT"
