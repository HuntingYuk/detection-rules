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

## Latest result (2026-05-19, post OVERLAP-audit + category-deepening, ET Open 50,169 enabled rules)

```
attack pcaps measured        : 94
GAP  ours fires / ET silent  : 75   <- custom corpus value-add (§17)
OVERLAP both fire            : 19   (ET Open already covers; audited below)
MISS ours did NOT fire       : 0   (gate guarantees 0  ✓)
ET Open FP on our benign     : 2 / 94  (caveat: negatives tuned to OUR rules)
```

**Read:** 75/94 attacks are caught **only** by the custom corpus — the concrete §17
evidence the set is worth maintaining. Three category-deepening batches (2026-05-19)
added 15 rules; 14 pure-GAP + 1 audited OVERLAP each batch on average, raising GAP
62→75. All 19 OVERLAP rules were individually audited (see "OVERLAP audit" below):
each is kept with a recorded reason (ours strictly better, ET misclassifies/only
generic, or deliberate ET-independent CVE backbone); one generic duplicate (9130003)
was retired. `MISS=0` confirms the merged-traffic context does not regress any rule
vs its isolated gate run, and that deprecated rules are correctly excluded.

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

---

## OVERLAP audit (2026-05-19)

`scripts/benchmark --audit-overlap` prints, per OVERLAP attack, our rule and the ET
Open rule(s) that co-fired. Every OVERLAP rule was reviewed against its ET
co-firing. **Guiding principle:** "do not depend on ET" is a foundational project
decision — an ET Open rule also covering ours is *expected* and is **not** grounds
to retire, because that would re-introduce the dependency the corpus exists to
avoid. A rule is retired only if it is a *generic, non-CVE-backbone* technique for
which ET has a mature exact equivalent **and** there is no independence rationale.

Result: **1 retired, 19 kept** (each with a recorded reason).

### Retired

| SID | Co-fire | Reason |
|---|---|---|
| 9130003 | ET 2019880 (Double Encoded Characters in URI `../`) | Exact functional duplicate; generic traversal technique, not part of the clean-room CVE backbone; no ET-independence argument. `rulectl deprecate`d (excluded from detection/export/benchmark; `config/deprecated.log`). |

### Kept — ours is strictly better or ET's match is illusory

| SID | ET co-fire | Why kept |
|---|---|---|
| 9100003 | 2062928 | ET only fired a *HUNTING*-tier rule, not an alert-grade SQLi rule; ours is the specific error-based detector. |
| 9130002 | 2013001, 2056494 | Ours uses `http.uri.raw` + all `php://` wrappers; ET's precise match is hunting-tier filter-chains only. |
| 9160001 | 2024668/9 | ET's rules are Struts2-REST-scoped; ours is generic Java serialized-object (`rO0AB`) on any endpoint. |
| 9160003 | 2053461 | **ET misclassifies** — matched the `exec` substring as "SQL Injection"; ours is the correct node-serialize detection. |
| 9190002 | 2053461 | **ET misclassifies** — same `exec`→"SQL Injection"; ours is the correct JSP-webshell detection. |
| 9300018 | 2048583 | Different kill-chain phase: ours = implant *access* (inbound); ET = implant *check* (outbound). Complementary. |
| 9300014 | 2011768, 2060800 | ET 2060800 is only the soft-hyphen variant; ours covers the core PHP-CGI argument-injection family. |
| 9410001 | 2018275/6 | ET's are single-malware-family signatures (Linux/Onimiki); ours is a generic DNS-tunnel heuristic. |
| 9210003 | 2031502 | ET 2031502 is INFO-tier and fires on the *request* (`GET /.env` fetch attempt — could be a harmless 404 scan); ours fires on the **secret actually disclosed in the response body** — opposite direction, confirmed-leak vs scan-attempt, Critical vs INFO. Strictly higher fidelity. |
| 9300029 | 2221028 | ET 2221028 is the generic SURICATA engine anomaly "HTTP Host header invalid" tripped by the oversized Host — no CVE context. Ours is the **CVE-2023-4966-specific** signature (OIDC discovery endpoint + oversized Host), giving actionable "Citrix Bleed exploitation" attribution vs a generic malformed-header anomaly. |
| 9430001 | 2001219, 2003068 | ET's are *SCAN* (recon) rules; ours is an attempted-admin **brute-force** rate rule — different classtype/intent. Kept; same network signal but distinct alert semantics for the pipeline. |

### Kept — clean-room CVE backbone, deliberately ET-independent

ET Open also ships a precise CVE rule for each; ours is **equally** CVE-specific
(none generic, none strictly worse). Kept on purpose so the corpus owns a
SID-stable rule + PoC + MITRE metadata that does not depend on the ET Open feed
remaining available/unchanged:

`9300001` Log4Shell · `9300006` F5 iControl · `9300008` FortiOS SSL VPN ·
`9300012` Ivanti Connect Secure · `9300017` PaperCut · `9300020` Bitbucket ·
`9300023` PAN-OS GlobalProtect · `9300026` GoAnywhere MFT.

This audit is reproducible: `scripts/benchmark --audit-overlap` regenerates the
co-firing evidence; `config/deprecated.log` records the retirement.

---

## Quality audit (2026-05-20)

Full pass at 99 active rules (`rulectl stats`, `lint -v`, PCRE scan, conf/threshold
sanity). Lint clean (0 warnings). Findings + actions:

### Fixed (D5 violations — unbounded `.*` in pcre, real backtracking risk)
- **9300008** FortiOS: `\?.*lang=.*` → bounded `\?[^\r\n]{0,80}lang=[^\r\n]{0,120}?`. `rev:2`.
- **9300015** GitLab: `[^&]*&.*` → bounded `[^&\r\n]{0,200}&[^\r\n]{0,400}?`. `rev:2`. PoC still fires post-fix.

### Fixed (ATT&CK accuracy)
- **9210004** Python-traceback leak: was `TA0007 Discovery` for T1592, but T1592 lives
  under TA0043 Reconnaissance — corrected. `rev:2`.

### Accepted trade-offs (4 short fast_patterns, §19 P1)
`rulectl stats` flags 4 rules whose fast_pattern is <5 bytes. Each is the **shortest
attacker-unique selector** for its CVE/leak class; extending the literal would shrink
coverage (e.g. an AWS access-key id IS literally `AKIA`+16, there is no longer
unambiguous prefix). pcre tightly bounds in every case:

| SID | fast_pattern | Why short is fine |
|---|---|---|
| 9210001 | `AKIA` | AWS access key id format is exactly `AKIA` + 16 upper-alnum — no longer literal exists. Bounded pcre `\bAKIA[0-9A-Z]{16}\b`. |
| 9300003 | `${(#` | Confluence OGNL opener (CVE-2022-26134). Unique to the exploit URL; bounded pcre confirms OGNL member-access right after. |
| 9300004 | `() {` | Shellshock bash function-def header (CVE-2014-6271). Unique to bash function syntax; no benign HTTP header carries `() {`. |
| 9300005 | `%{(#` | Struts2 S2-045 OGNL in Content-Type (CVE-2017-5638). Unique to Struts2 OGNL in a header; pcre anchors it to Content-Type. |

These four are **acknowledged**, not bugs.

### Non-payload rules (no `fast_pattern` by design — §22 C1)
18 rules: dns-tunnel ×3, l34-recon ×5, tls-anomaly ×3, infra-bruteforce ×1,
protocol-anomaly ×9, +9410001/2/3, +9420001..5. Each is rate/anomaly/dataset-anchored;
the pcre/flags/keyword IS the selector. Correctly absent fast_pattern.
