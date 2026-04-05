##### 10.1.2.105

## 1. Information Gathering

### 1.1 Port Scanning

Pertama-tama dilakukan pemindaian port menggunakan **Rustscan** untuk mengidentifikasi service-service yang terbuka pada target.

```bash
rustscan -a 10.1.2.105 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

Hasil pemindaian menunjukkan beberapa port terbuka:

|Port|Service|Keterangan|
|---|---|---|
|22/tcp|SSH|OpenSSH 6.0p1 Debian 4+deb7u7|
|80/tcp|HTTP|Apache httpd 2.2.22 (Debian) - Joomla CMS|
|443/tcp|HTTPS|SSL/TLS - TurnKey Linux|
|12320/tcp|HTTP|ShellInABox httpd|
|12321/tcp|HTTP|MiniServ 1.630 (Webmin)|
|12322/tcp|HTTPS|Apache + phpMyAdmin|
### 1.2 Web Service Enumeration

#### Joomla (Port 80/443)

Dari hasil `whatweb` diketahui bahwa target menjalankan **Joomla! CMS version 2.5.9** dengan PHP 5.4.4.

```bash
whatweb https://10.1.2.105
```

Hasil:

- MetaGenerator: Joomla! - Open Source Content Management - Version 2.5.9
    
- PHP Version: 5.4.4-14+deb7u5
    
- Apache Version: 2.2.22 (Debian)
    

#### phpMyAdmin (Port 12322)

```bash
whatweb https://10.1.2.105:12322
```

Ditemukan service **phpMyAdmin** dengan versi yang sudah cukup tua.

#### ShellInABox (Port 12320)

```bash
whatweb https://10.1.2.105:12320/
```

Teridentifikasi sebagai **Shell In A Box** - web-based terminal emulator.

#### Webmin (Port 12321)

```bash
whatweb http://10.1.2.105:12321
```

Teridentifikasi **MiniServ 1.630** (Webmin).

## 2. Vulnerability Identification

### 2.1 phpMyAdmin - Default Credentials

Berdasarkan dokumentasi TurnKey Linux, **phpMyAdmin** memiliki konfigurasi default dengan username `adminer` dan password kosong. Hal ini merupakan konfigurasi bawaan dari **TurnKey Linux Joomla Appliance**.

### 2.2 Joomla - Default Credentials

Joomla pada appliance ini juga menggunakan kredensial default:

- **Username:** `admin`
    
- **Password:** `admin`
    

---

## 3. Exploitation

### 3.1 Login ke phpMyAdmin

Akses halaman phpMyAdmin pada port 12322 dan login menggunakan kredensial default:

```text
URL: https://10.1.2.105:12322/
Username: adminer
Password: (kosong)
```
tetapi tidak ditemukan apa apa

### 3.2 Login ke Joomla Admin Panel

Gunakan kredensial default untuk mengakses Joomla administrator:

```text
URL: https://10.1.2.105/administrator/
Username: admin
Password: admin
```

### 3.3 Upload Reverse Shell via Template Manager

Setelah berhasil login sebagai administrator Joomla, langkah selanjutnya adalah mengunggah **reverse shell** melalui Template Manager:

1. Buka menu **Extensions → Templates → Templates**
    
2. Pilih template aktif (dalam kasus ini: **beez20**)
    
3. Buat file baru atau edit file `index.php`
    
4. Masukkan kode **Python reverse shell**

5. Simpan perubahan dan akses file template untuk memicu reverse shell

pergi ke templates manager > beez20 > menggunakan python reverse shell baru berhasil
## 4. Post-Exploitation

### 4.1 Enumeration User

Dari shell yang diperoleh, lakukan enumerasi user dengan membaca file `/etc/passwd`:

```bash
cat /etc/passwd
```

Hasil menunjukkan beberapa user penting, termasuk `cobra` dan `root`.

### 4.2 Membaca Configuration.php

Untuk mendapatkan kredensial database, baca file `configuration.php` Joomla:

```bash
cat /var/www/joomla/configuration.php
```

Diperoleh informasi kredensial database:

```php
public $user = 'joomla';
public $password = 'ffe6ffb03ff24334f12ebe26d501d4c8';
public $db = 'joomla';
```

### 4.3 SSH Login sebagai Root

Dengan menggunakan kredensial yang diperoleh (atau melalui privilege escalation), lakukan login SSH sebagai user `root`:

```bash
ssh root@10.1.2.105
```
