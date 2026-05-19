# PoC — SID 9190003 (php-create-function)

- Rule file: `rules/plaintext/webshell.rules`
- Expected: `poc.sh` fires SID `9190003`; `negative.sh` does NOT (but DOES hit the fast_pattern `create_function(`).
- Technique: PHP code-injection webshell — `create_function('','system($_POST[1]);')` wired to a superglobal, posted in the request body. Distinct from the `@eval($_POST` (9190001) and JSP `getRuntime().exec` (9190002) webshell variants.
- Suricata gate version: record `suricata -V` output when first green.
- Type: single-event.
