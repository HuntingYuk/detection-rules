# HuntingYuk Detection Rules

Private detection content for the HuntingYuk org. Custom, low-false-positive,
PoC-proven. **Not** a bulk ruleset import.

```
suricata/
  rules/plaintext/    rules that need decrypted HTTP visibility
  rules/tls-meta/     rules that work on TLS metadata / non-HTTP plaintext
  tests/poc/<sid>_<slug>/   per-rule PoC + negative + README (1:1 traceability)
  tests/fixtures/<family>/  shared golden pcaps for threshold/flowbit/TLS families
  config/             classtypes, thresholds, test suricata.yaml
  scripts/            rulectl (authoring CLI), verify.sh (DoD gate)
```

- **Add a rule:** see `CLAUDE.md` → Quickstart. Never hand-pick a SID; use
  `scripts/rulectl sid-next <category>` (or `rulectl new`).
- **Gate:** no rule lands without `scripts/rulectl check <sid>` green (PoC fires the
  exact SID, negative stays silent, `suricata -T` clean, metadata valid).
- **Sourcing:** 100% custom hand-written. ET PRO is an offline reference + private
  indicator source only — never copied. `etpro-*` scripts are LICENSE-GATED and
  refuse to run until the ET PRO license clause is recorded (see CLAUDE.md).
- **Brainstorming / design specs are intentionally NOT in this repo** (gitignored) —
  the org consumes only the final, reviewed artifacts.

Design source of truth (internal, not committed): the reviewed spec, kept by the
maintainer. This repo is the *implementation*.
