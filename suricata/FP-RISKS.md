# FP-RISKS.md — known & suspected false-positive surface per rule

> Trade-off policy: **we don't blanket-tighten rules at the cost of missing real
> attacks.** This doc warns operators where FPs may surface, so you tune
> per-deployment (`config/threshold.config` by dst) instead of having a rule
> that silently misses a real exploit because we hardened it preemptively.
> Empirical probe: `scripts/audit-fp` → `AUDIT-FP.md` (re-run anytime).

## Headline

- 119 active rules, 119 hand-crafted negatives all green.
- **Empirical FP probe (64 broad-benign scenarios): 2 alerts** — both **known
  residual, kept by design** (see §1).
- The rest of this doc is **analytical** — categories of FP that probes won't
  always catch, and the tuning playbook.

---

## §1 Empirical residuals — KEPT BY DESIGN

The `scripts/audit-fp` probe hits 2 alerts on benign-shaped traffic. Both are
real residuals; tightening either rule would create a *miss path* that's
worse than the FP itself.

### 9150003 — SSRF to GCP cloud metadata hostname

- **Fires on**: `GET /docs?q=metadata.google.internal+...` (a docs/search URL
  that *contains* the hostname after any `=`).
- **Why**: the pcre is `(?::\/\/|%3a%2f%2f|=|%3d)metadata.google.internal` —
  the `=` clause catches `?url=metadata.google.internal` (SSRF where the app
  prepends a scheme), but as a side effect it also catches `?q=metadata...`
  (search query with the hostname as text).
- **Why we keep it loose**: real SSRF often arrives as `?host=<hostname>` or
  `?url=<bare-host>` without an explicit `://` — many vulnerable apps
  concatenate the scheme server-side. Requiring `://` would miss those.
- **Tune**: if your docs/search backend frequently mentions GCP metadata, add
  the docs hostname to `config/threshold.config` (suppress dst-side) or
  `threshold:type limit, track by_dst, count 1, seconds 86400` to once-per-day.
- **Residual rate (caveat)**: synthetic-corpus; real-traffic rate likely 0
  unless you host cloud-engineering docs.

### 9210002 — PEM private key in HTTP response body

- **Fires on**: a docs/help response that quotes the PEM header `-----BEGIN
  PRIVATE KEY-----` as text without an actual key body following.
- **Why**: the pcre is just `-----BEGIN (?:RSA |EC |...)?PRIVATE KEY-----`.
  Adding a base64-body requirement (e.g. `[A-Za-z0-9+/]{50,}` after) would
  miss legitimate-leak cases where the response is truncated, chunked, or the
  PEM body is base64-wrapped/encoded differently. Per `§19 D2` format-unique
  headers are kept as the anchor.
- **Tune**: `threshold:type threshold, track by_dst, count 1, seconds 3600`
  for known docs hosts; or full suppression for `helpcenter.<yourorg>` etc.
- **Residual rate**: synthetic; real risk only on public docs hosts that
  literally print PEM headers in tutorial copy.

---

## §2 Analytical FP risk by rule category

### Path-only known-CVE rules (LOW FP — most of `known-cve.rules`)

Rules whose detection is *just* an exploit-targeted endpoint path
(`/mgmt/tm/util/bash`, `/vpns/portal/`, `/sslvpn_websession`,
`/setup/setupadministrator.action`, `/moveitisapi/moveitisapi.dll`,
`/json/setup-restore`, `/SetupWizard.aspx/`, `/oauth/idp/.well-known/...`,
`/admin/configurenewlanguage.action`, `/remote_agent.php`,
`/password_change.cgi`, `/vendor/phpunit/.../eval-stdin.php`, etc).

**FP risk**: low. These paths are vendor-specific exploit endpoints; legit
clients don't fetch them. **Residual**: legit security scanners
(Nessus/Nuclei/qualys) that probe these very paths — which is the rule
*correctly* firing on a recon attempt against you. Treat as recon noise from
known-scanner IPs (suppress src-side once attributed).

### Threshold / rate rules (MEDIUM FP — depends on traffic mix)

`9180001` HTTP login flood (POST/login 20/60), `9180002` Basic-Auth spray
(30/60), `9430001` SSH brute (SYN/22 20/60), `9430002` RDP brute (SYN/3389
30/60), `9420001..5` L3/L4 recon (various), `9500004/6/8/9` protocol-anomaly
rate, `9410001..3` DNS-tunnel volume.

**FP triggers**:
- Load testing / chaos engineering against your own infra.
- A monitoring system polling login or basic-auth endpoints repeatedly.
- Service-mesh sidecar opening many short-lived TCP connections to a backend.
- DNS log shippers / OpenTelemetry collectors emitting bursts of queries.

**Why we keep thresholds tight-ish**: too loose = real brute-force fits inside
one window. The values we shipped (20/60s SSH, 30/60s RDP, 30/60s Basic) are
the *minimum* that a tooled brute-force operator generates; legit operations
rarely match.

**Tune**:
- Allowlist load-tester source IPs in `threshold.config` (`suppress by_src`).
- Pin per-dst higher limits for known busy auth endpoints (a public-facing
  login that legitimately gets 60 POSTs/min can carry `threshold ... count 60
  seconds 60` on that dst alone).

### Pattern + pcre payload rules (LOW-MEDIUM — pcre keeps these tight)

Most of `sqli.rules`, `xss.rules`, `cmdi.rules`, `traversal.rules`,
`xxe.rules`, `deserialization.rules`, `webshell.rules`. Pcre is anchored
(structural; e.g. SQLi requires a tautology + boundary, XSS requires a
quote+`<script` adjacency).

**FP triggers** (rare but real):
- A pentest training site (HackTheBox/PortSwigger Academy) hosted on your
  perimeter that mirrors attack URLs back as docs/walkthrough text.
- A bug-bounty tracker that quotes exploit URLs in comments rendered server-side.
- A developer demo of a vulnerability for internal training.

**Why we keep pcre permissive of these edge cases**: a real attack often
appears with the same shape (anchored pattern); rejecting docs-shaped text
would require classifying docs vs attack from the URL alone, which is brittle.

**Tune**: tag any internal training/bug-tracker host as a "known-noisy" dst
and `threshold:type threshold, count 5, seconds 60, track by_dst` for it.

### Response-side info-leak rules (MEDIUM-HIGH on dev/staging — known issue)

`9210001..7` — AWS keys, PEM, AWS-secret-env, Python traceback, Spring
Whitelabel, Rails exception, Tomcat default error.

**FP triggers**:
- Dev or staging environments with `DEBUG=true` / verbose error pages
  enabled. These will fire 9210004/5/6/7 constantly.
- Documentation/help pages that *show* the format as a teaching example
  (the 2 empirical residuals in §1 are this).
- A staging tenant that hosts customer-uploaded test data with sample keys.

**Why we keep these format-only**: the format IS the leak; tightening to "key
body length" risks missing truncated/chunked leak responses. Per spec §19 D2
format-unique secrets are accepted as the anchor.

**Tune**: this is the textbook `threshold:type threshold, track by_dst, count
1, seconds 86400` (once-per-day per dst) case — alert the first leak per host
per day, suppress duplicate noise. Or fully suppress known-dev hosts:
`suppress gen_id 1, sig_id 9210004, track by_dst, ip <dev-host>`.

### Short-fast_pattern format-unique rules (LOW FP — pcre bounds tightly)

`9210001` `AKIA`, `9300003` `${(#`, `9300004` `() {`, `9300005` `%{(#` — the
4 rules `rulectl stats` weak/hot-flags. Each is the *shortest attacker-unique
selector* for its CVE/leak class. Documented in `BENCHMARK.md` "Quality audit
(2026-05-20)".

**FP risk**: low. The 4 literals are format-unique (AKIA = AWS key prefix;
`${(#` / `%{(#` = OGNL openers; `() {` = bash function header). Pcre
constrains in every case.

**Residual**: a documentation page literally listing all four would set off
several alerts — see §1 for the precedent and tuning.

### Two-buffer rules (VERY LOW FP — high specificity)

`9300029` Citrix Bleed (uri.raw + http.header `Host` length), `9300031`
Webmin (uri.raw + body metachar), `9300033` Jenkins (uri.raw + body `@/`),
`9300038` Spring Cloud Gateway (uri.raw + body SpEL), `9300039` Confluence
(uri.raw + body Runtime gadget).

**FP risk**: very low. Both buffers must match independently; the joint
probability of a benign request satisfying both is near zero. These are the
*most reliable* rules in the corpus.

### Non-payload `flags`/threshold rules (LOW FP — deterministic)

`9500001/2/3/5` illegal TCP-flag combinations (SYN+FIN, Xmas, NULL, SYN+RST) —
no legit TCP stack emits these.

**FP risk**: ~0. These literally cannot happen in a healthy TCP stream.
**Residual**: misconfigured network appliance, fuzzing test traffic.

### TLS-meta / DNS rules (LOW-MEDIUM)

`9400001` SNI bare-IPv4 literal, `9400002` JA3 dataset, `9400003` expired
cert, `9410001..3` DNS-tunnel.

**FP triggers**:
- SNI bare-IP: some IoT/older clients connect via SNI=IP (broken-by-design
  but exists in the wild). Tune by allowlisting known-quirky src/dst.
- JA3 dataset: misclassified entry. Mitigated by curated dataset + expire
  date convention (spec §22 D6).
- Expired cert: a *test* TLS host you forgot to rotate. Suppress by dst.
- DNS-tunnel volume: long base32/hex labels also appear in cookie-tracking
  CDN URLs, A/B-test framework callbacks, and some legitimate enterprise
  software (Sophos cloud lookup, etc.). The threshold helps but a steady
  legit source can sustain false alerts.

---

## §3 Tuning playbook (`config/threshold.config`)

When an FP hits in production, the order of escalation is:

1. **Per-dst suppress** (most surgical):
   ```
   suppress gen_id 1, sig_id <SID>, track by_dst, ip <known-dev-host>
   ```
2. **Per-src suppress** (if it's a known scanner you authorize):
   ```
   suppress gen_id 1, sig_id <SID>, track by_src, ip <pentest-bastion>
   ```
3. **Per-dst rate limit** (alert once per day, useful for response-side leak
   rules on slow-moving dev hosts):
   ```
   threshold gen_id 1, sig_id <SID>, type limit, track by_dst, count 1, seconds 86400
   ```
4. **Global threshold** (a last resort — risks missing real attacks):
   ```
   threshold gen_id 1, sig_id <SID>, type threshold, track by_src, count 5, seconds 60
   ```

Per spec §22 C2 and CLAUDE.md §11, `threshold.config` is **temporary tuning,
not retirement**. If a rule keeps FP-ing across many deployments, the right
fix is to retire it via `rulectl deprecate` (with the OVERLAP-audit pattern
in `BENCHMARK.md`), not to keep growing the suppression list.

---

## §4 What this doc is NOT

- It is **not** a guarantee. Real traffic is messier than `audit-fp`'s 64
  scenarios. Re-run the probe after each batch; add real-pcap dirs via
  `scripts/benchmark --pcap-dir/--benign-dir` once available.
- It is **not** a license to ship every rule everywhere. Use `rulectl
  export --network-mode tls-meta` / `--owasp A03` / `--meta confidence=high`
  to ship only the slices you want per-sensor.
- It is **not** a substitute for honest tuning per-customer. Every deployment
  has its own benign-noise profile; the threshold playbook (§3) is the
  knob, not a one-off corpus rewrite.
