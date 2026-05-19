# PoC — SID 9100005 (mssql-xp-cmdshell)

- Rule file: `rules/plaintext/sqli.rules`
- Expected: `poc.sh` fires SID `9100005`; `negative.sh` does NOT (but DOES hit the fast_pattern `xp_cmdshell`).
- Technique: SQLi escalating to MSSQL OS command execution via `EXEC master..xp_cmdshell(...)`. HIGH confidence (deterministic attacker-unique) — no detection_filter, unlike the pattern-based sqli variants 9100001–9100004.
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event.
