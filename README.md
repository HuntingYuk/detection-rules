# HuntingYuk Detection Rules

[![rule-gate](https://github.com/HuntingYuk/detection-rules/actions/workflows/gate.yml/badge.svg)](https://github.com/HuntingYuk/detection-rules/actions/workflows/gate.yml)

Hand-written, **low-false-positive, PoC-proven** Suricata detection content. Every
rule is clean-room derived from primary sources (NVD advisories, public PoCs,
nuclei-templates MIT, observed real-world scanner traffic) and proven on real
Suricata before it lands. Not a bulk-ruleset import.

## Coverage (live — run `scripts/rulectl stats` or read `rules.json`)

**144 active rules** (1 deprecated). Confidence: 112 high · 32 medium (every
medium has documented FP reasoning + threshold/detection_filter compensator).
Network mode: 122 plain · 19 any · 3 tls-meta.

| Family | # | What it catches |
|---|---|---|
| **OWASP injection/RCE** | 50 | sqli ×6 · cmdi ×11 · xss ×5 · traversal ×5 · xxe ×3 · ssrf ×3 · deserialization ×7 · webshell ×4 + misc A02 JWT-alg:none |
| **Recon / exposure** | 16 | access-control ×7 (`.git/.aws/.svn/.env`, `/phpinfo`, `/_profiler`, `/server-status`) · recon-http ×2 (sqlmap/nuclei UA) · info-leak ×7 |
| **Known-CVE backbone** | 47 | Log4Shell (+obfuscated bypass), Spring4Shell, Confluence (OGNL+22515+22518+21683), Shellshock, Struts2 (S2-045+REST XStream), F5, Citrix (19781+Bleed), FortiOS, Exchange (ProxyLogon+ProxyShell), MOVEit, Ivanti, OFBiz, PHP-CGI, GitLab, Spring Cloud (Function+Gateway), PaperCut, Cisco IOS XE, ColdFusion, Bitbucket, TeamCity, ScreenConnect, PAN-OS GlobalProtect, Zimbra, vCenter, GoAnywhere, PulseSecure, GeoServer, ActiveMQ Jolokia, Webmin, PHPUnit, Apache HTTPD 41773, Drupalgeddon2, CrushFTP, ownCloud, Magento CosmicSting, WP Bricks, Cleo Harmony, ThinkPHP, GPON, MVPower DVR, D-Link HNAP1, Netgear DGN, Realtek SDK, TBK DVR, Linksys mp, LB-Link, QNAP Viostor, Tuoshi NTP, Apache Tomcat 24813 |
| **Network / infra (no decrypt)** | 25 | protocol-anomaly ×9 · l34-recon ×5 · dns-tunnel ×3 · tls-anomaly ×3 (SNI-IP, JA3-dataset, expired-cert) · infra-bruteforce ×2 (SSH, RDP) · auth-bruteforce ×2 (login flood, Basic-Auth spray) |

## §17 honest scoreboard vs ET Open (50,169 enabled rules)

| Bucket | Count | Meaning |
|---|---|---|
| **GAP** | **111 / 144** | Attacks ONLY our corpus catches — the §17 value-add |
| OVERLAP | 33 | ET also covers — audited & KEPT (1 retired, 32 kept; see `suricata/BENCHMARK.md`) |
| MISS | 0 | Gate-enforced invariant |

**Real-traffic validation** (`scripts/benchmark-real` against MTA "scans-and-probes"
captures): corpus fires **20 distinct SIDs (2,839 alerts)** on 3 real perimeter-scan
pcaps — every fired rule = real attacker behaviour (PHPUnit CVE-2017-9841 933×,
`.env` probes 917×, `/.git/config` 214×, port-scans 121×, PHP-CGI CVE-2024-4577 92×,
SNI=bare-IP 53×, Shellshock 32×, + others). See `suricata/AUDIT-REAL.md` and
`suricata/AUDIT-REALGAP.md` for the full data-driven backlog.

## Manifest — `rules.json` + per-category split

Single source of truth for every rule with full metadata:

```
rules.json                      ← lightweight INDEX (~75 KB)
                                  corpus stats + per-rule {sid, msg, owasp,
                                  confidence, cve, §17 status, ref}
rules/by-category/<cat>.json    ← FULL DETAIL (19 files, 2-160 KB each)
                                  metadata + fast_pattern + pcre + buffers +
                                  poc_dir + readme + description + raw alert
```

Downstream tooling: load `rules.json` for the index, follow each rule's
`ref` field to fetch the per-category detail. Drift-gated by
`gen-manifest --check` in CI.

## Deployment bundles (`suricata/bundles/`)

Pre-built `.rules` + `.index.json` sidecars for common deployment slices. Gitignored
(derived); regenerate with `suricata/scripts/release`:

| Bundle | Use case |
|---|---|
| `all.rules` | Everything — central NSM / large SOC |
| `high-confidence.rules` | Noisy/large perimeters — minimise FP |
| `plaintext.rules` | Sensor decrypts TLS / sees cleartext HTTP |
| `tls-meta.rules` | Sensor sees only TLS handshake metadata (no decryption) |
| `any.rules` | L3/L4 + DNS — deploy anywhere, no decryption |
| `known-cve.rules` | Perimeter-targeted CVE exploitation only |
| `owasp.rules` | OWASP Top-10-only deployments (compliance-driven) |
| `auth-access-leak.rules` | Recon / credential-attack / exposure-only watch |

Each bundle has a sha256 in `suricata/bundles/README.md` for tamper-evident
pinning.

## Layout

```
suricata/
  rules/plaintext/                 network_mode=plain (needs decrypted HTTP)
  rules/tls-meta/                  network_mode=tls-meta|any (no decrypt)
  tests/poc/<sid>_<slug>/          per-rule PoC + negative + README (1:1, generated)
  tests/poc/_descriptions.json     human-written prose source (gate-required)
  tests/poc/_bench_status.json     §17 GAP/OVERLAP snapshot (regenerable)
  bundles/                         pre-built deployment .rules (gitignored)
  config/                          classtypes, thresholds, reference, test suricata.yaml
  scripts/                         see Tooling below
  BENCHMARK.md                     §17 method + OVERLAP audit table
  FP-RISKS.md                      per-rule false-positive risk + tuning playbook
  AUDIT-TRAFFIC.md                 cross-fire + negative-adequacy matrix
  AUDIT-REAL.md                    real-traffic ruleset-vs-ET on MTA pcaps
  AUDIT-REALGAP.md                 data-driven backlog from real-traffic gaps
  AUDIT-FP.md                      empirical FP probe across 64 benign scenarios
rules.json                         single-source manifest (index)
rules/by-category/<cat>.json       per-category full detail
CATALOG.md                         human-readable rule catalog
```

## Tooling — `suricata/scripts/`

| Script | Purpose |
|---|---|
| `rulectl` | Full lifecycle: `sid-next` · `new` · `validate-meta` · `lint` · `test` · `check` · `ci` · `stats` · `list` · `export` · `deprecate` · `diff` |
| `gen-docs` | Generate per-PoC README + CATALOG.md from `_descriptions.json` |
| `gen-manifest` | Generate `rules.json` index + `rules/by-category/*.json` detail |
| `release` | Generate deployment bundles into `bundles/` |
| `benchmark` | §17 measurement vs ET Open control (synthetic PoC corpus) |
| `benchmark-real` | Real-pcap measurement (`--pcap-dir` / `--benign-dir`) |
| `audit-fp` | 64 benign scenarios → FP candidate report (`AUDIT-FP.md`) |
| `audit-traffic` | Cross-fire matrix + negative-adequacy (`AUDIT-TRAFFIC.md`) |
| `audit-realgap` | Real-traffic ET-exploit-class gap analysis → data-driven backlog |
| `fetch-mta` | Download recent MTA pcap exercises → `reference/mta/` (gitignored) |

## Add a rule

```bash
cd suricata
scripts/rulectl new <category> --slug <s> --conf high|medium --network-mode plain|tls-meta|any
# 1. edit the one generated rule line + fill poc.sh / negative.sh
# 2. add tests/poc/_descriptions.json entry: {sid: {attack, impact, detects}}
scripts/gen-docs                  # regenerate README/CATALOG from JSON
scripts/gen-manifest              # regenerate rules.json + per-category split
scripts/rulectl check <sid>       # lint + validate-meta + PoC fires + negative silent
git commit -m "feat(<cat>): <sid> ..."
```

Never hand-pick a SID. Never put a `#` inside a rule body.

## Self-regressing gate

Every push & PR runs `scripts/rulectl ci` on Suricata 8.x via
`.github/workflows/gate.yml`:

1. `lint` — `suricata -T` clean
2. `validate-meta` — controlled vocab + dup-SID + folder↔network_mode
3. `gen-docs --check` — per-PoC README drift
4. `gen-manifest --check` — `rules.json` + per-category drift
5. **Per-rule test** — PoC pcap fires the target SID, negative pcap doesn't

Red badge = a rule regressed; nothing merges past a failing gate.

## Sourcing & licensing

Logic-derivation only — never verbatim — re-expressed with our metadata + SID +
PoC. MIT/public sources (nuclei-templates MIT, NVD, vendor advisories, public
PoCs, malware-traffic-analysis.net Brad Duncan captures for behavioural reference)
are unrestricted; all rules come from these clean-room. **ET PRO** is
license-gated: `etpro-*` scripts refuse to run until the verbatim governing license
clause is recorded.

## Sources tested against

- **malware-traffic-analysis.net** (Brad Duncan) — daily real-malware + perimeter
  scan captures. Validates the corpus fires correctly on real attacker traffic.
  Fetch via `scripts/fetch-mta`. Pcaps stay local (`reference/mta/` gitignored).
  Attribution required when publishing results.
- **ET Open** (suricata-update) — the §17 control. License-clean to reproduce
  locally, not redistributed.
