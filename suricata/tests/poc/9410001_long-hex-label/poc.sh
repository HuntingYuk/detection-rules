#!/usr/bin/env bash
# PoC for SID 9410001 (DNS tunnel). FIXTURE-REPLAY type (spec §19 T3 + UC3): replays
# the committed golden fixture from the shared dns-tunnel family pool. 20 long-hex
# label queries from one src -> trips detection_filter count 15 -> SID 9410001 fires.
# Regenerate the fixture with: tests/fixtures/dns-tunnel/gen.py
set -euo pipefail
OUT="${1:?usage: poc.sh <out.pcap>}"
DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$DIR/../../fixtures/dns-tunnel/poc.pcap" "$OUT"
