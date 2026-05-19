# HuntingYuk Detection Rules

[![rule-gate](https://github.com/HuntingYuk/detection-rules/actions/workflows/gate.yml/badge.svg)](https://github.com/HuntingYuk/detection-rules/actions/workflows/gate.yml)

Private, custom, **low-false-positive, PoC-proven** Suricata detection content for
the HuntingYuk org. Not a bulk ruleset import — every rule is hand-derived from
primary sources and proven on real Suricata before it lands.

## Coverage (60 rules — run `scripts/rulectl stats` for the live matrix)

| Area | Rules |
|---|---|
| OWASP injection/RCE | sqli ×3 · cmdi ×3 · xss ×2 · xxe ×2 · traversal ×2 · ssrf · deserialization ×2 |
| Auth / access / leak | access-control · auth-bruteforce · info-leak · webshell · recon-http · A02 JWT-alg:none |
| Known CVEs | **×18** — Log4Shell, Spring4Shell, Confluence (OGNL + 2023-22515), Shellshock, Struts2, F5, Citrix, FortiOS, ProxyShell, MOVEit, Ivanti, OFBiz, PHP-CGI, GitLab, Spring Cloud Function, PaperCut, Cisco IOS XE |
| Network / infra (no decrypt) | protocol-anomaly ×9 · l34-recon ×5 · dns-tunnel ×3 · tls-anomaly ×3 · infra-bruteforce |

35 high-confidence / 25 medium (every medium has documented FP reasoning + a
threshold/detection_filter compensator). 39 `plain` · 18 `any` · 3 `tls-meta`.

## Layout

```
suricata/
  rules/plaintext/          network_mode=plain   (needs decrypted HTTP)
  rules/tls-meta/           network_mode=tls-meta|any (no decrypt needed)
  tests/poc/<sid>_<slug>/   per-rule PoC + negative + README (1:1)
  tests/fixtures/<family>/  shared golden pcaps (threshold/flowbit/TLS)
  config/                   classtypes, thresholds, reference, test suricata.yaml
  scripts/                  rulectl (full lifecycle), verify.sh, etpro-* (gated)
```

## Add a rule

```bash
cd suricata
scripts/rulectl new <category> --slug <s> --conf high|medium --network-mode plain|tls-meta|any
#   edit the one generated rule line + fill poc.sh / negative.sh
scripts/rulectl check <sid>      # lint + validate-meta + PoC fires + negative silent
git add -A && git commit -m "feat(<cat>): <sid> ..."
```

Never hand-pick a SID. Never put a `#` inside a rule. Full contract: **`CLAUDE.md`**
(SID procedure, metadata schema, FP discipline, sourcing policy, Suricata-8 gotchas).

## Gate (self-regressing)

Every push & PR runs `scripts/rulectl ci` (lint + validate-meta + PoC/negative for
**every** rule) on OISF Suricata 8.x via `.github/workflows/gate.yml`. A red badge =
a rule regressed; nothing merges past a failing gate.

`rulectl` verbs: `new sid-next validate-meta lint test check ci stats list export
(+sidecar index) deprecate diff`.

## Sourcing & licensing

Logic-derivation only — never verbatim — re-expressed with our metadata/SID/PoC.
MIT/public sources (nuclei-templates MIT, NVD, vendor advisories, public PoCs) are
unrestricted; all current rules come from these, clean-room. **ET PRO is
license-gated**: `etpro-*` and any ET network access refuse to run until the verbatim
governing license clause is recorded in `suricata/config/ET-LICENSE.md` (see
CLAUDE.md §13 — logic-derivation from ET PRO is itself the derivative-work question
that clause governs).

Brainstorming / design specs are intentionally **not** in this repo (gitignored);
the org consumes only the final, reviewed, gate-passing artifacts.
