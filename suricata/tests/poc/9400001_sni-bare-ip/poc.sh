#!/usr/bin/env bash
# PoC SID 9400001. FIXTURE-REPLAY (spec §19 T3): committed golden TLS pcap with a
# ClientHello whose SNI is a bare IPv4 literal. Provenance: tests/fixtures/tls-anomaly/gen.py
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
cp "$(cd "$(dirname "$0")" && pwd)/../../fixtures/tls-anomaly/mal.pcap" "$OUT"
