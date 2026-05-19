# §17 success metric — custom corpus vs a tuned ET Open control

Spec §17 asks one question: **does this hand-written corpus earn its keep next to a
free public ruleset?** `scripts/benchmark` answers it without hand-waving — it runs
the *exact same traffic* through our ruleset and through ET Open, then diffs the
alerts per attack.

## What it measures

For every rule's PoC pcap (the attack the rule exists to catch):

| Bucket | Meaning |
|---|---|
| **GAP** | our rule fires, **ET Open is silent** → the attack only *we* catch. This is the §17 value-add. |
| **OVERLAP** | both fire → ET Open already covers it (kept only if measurably lower-FP — needs real traffic to judge). |
| **MISS** | our rule did **not** fire → must be 0; the gate (`rulectl ci`) guarantees every rule fires its own PoC. `MISS > 0` is a harness bug, not a result. |

Plus: ET Open's firings on our *negative* (benign-lookalike) pcaps — a **caveated**
false-positive signal (the negatives are tuned to trip *our* fast_patterns, not
sampled from production, so this is a smoke test, not a production FP rate).

## Method (and why each step exists)

1. **Regenerate** every `tests/poc/<sid>/{poc,negative}.sh` into a fresh pcap — same
   scapy harness the gate uses, so "fires here" == "fires in CI".
2. **Unique-IP rewrite + single merged pcap.** Suricata 8.0.4 does not emit
   `pcap_filename` in `eve.json`, so per-file attribution is impossible. Instead each
   pcap's client IP is rewritten to a unique `10.99.x.y`; all attacks concatenate
   into one pcap; an alert is attributed to an attack by its `10.99.` address. Both
   rulesets are therefore loaded **once** (50k ET rules load is ~slow — this matters).
3. **L4 checksums recomputed.** Rewriting the IP invalidates the TCP/UDP checksum
   (it covers the IP pseudo-header). The harness deletes `IP/TCP/UDP/ICMP.chksum` so
   scapy recomputes on write, **and** runs `suricata -k none` (ignore checksums on
   synthetic replay). Without this, the stream engine drops the rewritten flows and
   ~80 % of payload rules silently MISS — the original cause of a false `MISS=64`.
4. **Diff** ours vs ET per attribution IP → GAP / OVERLAP / MISS.

## Latest result (2026-05-19, ET Open 50,169 enabled rules)

```
attack pcaps measured        : 80
GAP  ours fires / ET silent  : 62   <- custom corpus value-add (§17)
OVERLAP both fire            : 18   (ET Open already covers)
MISS ours did NOT fire       : 0   (gate guarantees 0  ✓)
ET Open FP on our benign     : 2 / 80  (caveat: negatives tuned to OUR rules)
```

**Read:** 62/80 attacks are caught **only** by the custom corpus — that is the
concrete §17 evidence the set is worth maintaining. The 18 OVERLAP rules duplicate
ET Open on coverage; they justify themselves only if they are *measurably* lower-FP
on real traffic (see limitation below). `MISS=0` confirms the merged-traffic context
does not regress any rule vs its isolated gate run.

## Limitation — synthetic, not production

This is a **coverage-gap** measurement on a synthetic PoC corpus. It is *not* a
production false-positive rate: the negatives are adversarially shaped to our own
fast_patterns. The honest FP comparison needs real or replayed traffic.

The harness already supports it — point it at directories of real pcaps:

```bash
scripts/benchmark --pcap-dir  /path/to/attack-or-replay-pcaps \
                  --benign-dir /path/to/known-good-traffic
```

(`--benign-dir` optional; with real benign traffic the "ET Open FP" line becomes a
trustworthy number, and a future revision can add the symmetric "our FP" column.)

## Reproduce

```bash
# one-time: fetch the ET Open control (gitignored — license-clean, not redistributed)
suricata-update --suricata "$(command -v suricata)" \
  -o reference/et-open --data-dir reference/et-open/data

cd suricata && scripts/benchmark
```

ET Open ruleset and all raw benchmark output are **gitignored** — only this method
doc and the harness are versioned. The control is reproducible from the command
above; results are environment-dependent and meant to be re-run, not pinned.
