#!/usr/bin/env bash
# Negative for SID 9410001. FIXTURE-REPLAY. Decisive-condition negative (spec §19
# T2/T6): the benign fixture contains normal queries PLUS one 50-hex-char label that
# DOES match the rule's pcre (the decisive condition is exercised) but a single match
# is far below detection_filter count 15/60s -> MUST stay silent.
set -euo pipefail
OUT="${1:?usage: negative.sh <out.pcap>}"
DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$DIR/../../fixtures/dns-tunnel/benign.pcap" "$OUT"
