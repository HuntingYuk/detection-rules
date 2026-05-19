# SID 9210004 — Info leak: Python traceback / debug page in HTTP response

**Rule:** `rules/plaintext/info-leak.rules` · **Confidence:** high · **OWASP:** A01 Broken Access Control · **Severity:** Major · **Side:** response (to_client)

## Serangan apa ini?
Aplikasi (Django/Flask/dll) error tapi mode DEBUG masih aktif, sehingga
**stack trace Python mentah** ikut terkirim ke browser penyerang: path file di
server, potongan kode, nama variabel, versi framework. Penyerang sengaja memicu
error (input aneh) untuk memancing halaman traceback ini.

## Kalau kena, dampaknya?
Bocornya **struktur internal aplikasi**: path absolut, library & versinya, logika
kode, kadang kredensial/secret yang ikut tercetak di variabel. Ini bahan bakar
untuk serangan lanjutan yang jauh lebih tepat sasaran (mis. pilih exploit sesuai
versi yang bocor). Sering jadi langkah *Discovery/Recon* sebelum eksploitasi nyata.

## Apa yang rule ini deteksi?
Frasa `Traceback (most recent call last)` di **body response**, ditambah
struktur traceback nyata (`File "..."`, `line N`, `...Error:`) supaya halaman
dokumentasi yang cuma menyebut frasa itu tidak ikut alert. Residual: host
dev/staging yang memang menampilkan traceback → tuning per-dst via `threshold.config`
(pola sama seperti 9210002).

## PoC vs Negative
- `poc.sh` → response `500` berisi traceback Python asli → **harus** memicu SID 9210004.
- `negative.sh` → halaman bantuan yang menyebut frasa tanpa frame traceback → kena fast_pattern lalu **ditolak pcre** → TIDAK alert.

## Cara jalanin
```
scripts/rulectl check 9210004
```
Type: single-event (response-side; handshake + request + server response).
