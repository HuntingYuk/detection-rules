# SID 9160005 — .NET insecure deserialization (BinaryFormatter stream)

**Rule:** `rules/plaintext/deserialization.rules` · **Confidence:** high · **OWASP:** A08 Software & Data Integrity Failures · **Severity:** Critical

## Serangan apa ini?
Aplikasi .NET yang menerima objek "serialized" (mis. lewat `__VIEWSTATE`, cookie,
atau API) lalu men-deserialize-nya pakai `BinaryFormatter`/`LosFormatter`.
Penyerang mengirim objek hasil **ysoserial.net** — sebuah "gadget chain" yang,
saat di-deserialize, otomatis mengeksekusi perintah sistem.

## Kalau kena, dampaknya?
**Remote Code Execution** penuh di server aplikasi (jalan sebagai user app pool /
service). Ini salah satu bug paling parah di dunia .NET — langsung ambil alih server.

## Apa yang rule ini deteksi?
Magic header stream BinaryFormatter dalam bentuk base64: `AAEAAAD/////`
(itu base64 dari byte `00 01 00 00 00 FF FF FF FF`). String ini tidak pernah
muncul di data jinak. Berbeda dari rule 9160002 yang menyasar gadget XML/teks
(`ObjectDataProvider`); rule ini menyasar **stream biner mentah** yang di-base64.

## PoC vs Negative
- `poc.sh` → `__VIEWSTATE=AAEAAAD/////...<base64 stream>` → **harus** memicu SID 9160005.
- `negative.sh` → teks dokumentasi yang kebetulan memuat `AAEAAAD/////` tanpa stream base64 → kena fast_pattern lalu **ditolak pcre** → TIDAK alert.

## Cara jalanin
```
scripts/rulectl check 9160005
```
Type: single-event.
