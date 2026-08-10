#Management Wants a Word
### TryHackMe — Windows Forensics & Cryptography

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-red)](https://tryhackme.com/)
[![Category](https://img.shields.io/badge/Category-Forensics-blue)](https://tryhackme.com/)
[![Difficulty](https://img.shields.io/badge/Difficulty-Hard-orange)](https://tryhackme.com/)

---

## 📋 Overview

**Management Wants a Word** is a hard-difficulty TryHackMe forensics challenge focused on investigating artifacts left behind on a Windows system.

The investigation begins with a Windows user profile belonging to **Vera** and eventually becomes a multi-stage forensic investigation involving:

```text
Windows Registry
      ↓
LSA Secrets
      ↓
Windows DPAPI
      ↓
Chrome Local State
      ↓
Chrome AES-256 Key
      ↓
Chrome Login Data
      ↓
VeraCrypt Container
      ↓
PDF
      ↓
FLAG
```

The objective was not simply to locate the flag, but to understand how the artifacts were connected and use each discovery to move to the next stage.

---

# 🎯 Objectives

During the investigation I needed to:

* Analyze a Windows user profile.
* Identify relevant forensic artifacts.
* Investigate Windows Registry hives.
* Extract LSA secrets.
* Recover a Windows credential.
* Decrypt a DPAPI master key.
* Recover Chrome's encryption key.
* Analyze Chrome's SQLite databases.
* Decrypt a saved browser credential.
* Identify the VeraCrypt container password.
* Mount the encrypted container safely.
* Locate the final evidence.
* Recover the flag.

---

# 🧰 Tools

| Tool                   | Purpose                        |
| ---------------------- | ------------------------------ |
| `find`                 | Locate forensic artifacts      |
| `file`                 | Identify file types            |
| `xxd`                  | Inspect binary headers         |
| `sqlite3`              | Analyze Chrome databases       |
| `jq`                   | Parse JSON data                |
| `impacket-secretsdump` | Extract Windows secrets        |
| `impacket-dpapi`       | Decrypt DPAPI material         |
| `Python`               | Custom Chrome decryption       |
| `cryptography`         | AES-GCM decryption             |
| `cryptsetup`           | Open VeraCrypt containers      |
| `mount`                | Mount forensic image/container |
| `base64`               | Decode encoded data            |

---

# 🔎 Investigation

## 1. Initial Reconnaissance

The challenge provided a directory representing a Windows filesystem.

The first step was identifying the user profile:

```text
C/Users/vera/
```

I then searched for artifacts associated with:

* Chrome
* Windows credential protection
* Registry hives
* VeraCrypt
* Documents

Important locations included:

```text
C/Users/vera/AppData/Local/Google/Chrome/
C/Users/vera/AppData/Roaming/Microsoft/Protect/
C/Users/vera/Documents/
C/Windows/System32/config/
```

---

# 📂 2. Important Artifacts

The investigation identified several important files:

```text
SAM
SYSTEM
SECURITY
```

Windows registry hives.

```text
Protect/<SID>/<GUID>
```

DPAPI master key.

```text
Chrome/User Data/Local State
```

Chrome encryption metadata.

```text
Chrome/User Data/Default/Login Data
```

Stored browser credentials.

```text
Chrome/User Data/Default/History
```

Browser activity.

```text
Chrome/User Data/Default/Web Data
```

Autofill information.

```text
C/Users/vera/Documents/backup
```

Encrypted VeraCrypt container.

---

# 💾 3. VeraCrypt Container Discovery

The first major artifact was:

```bash
file C/Users/vera/Documents/backup
```

I also inspected the beginning of the file:

```bash
xxd -l 64 C/Users/vera/Documents/backup
```

The evidence indicated that `backup` was an encrypted VeraCrypt container.

At this point I had a container, but not its password.

That raised the next question:

> Where could Vera's password have been stored?

This led me toward the browser artifacts.

---

# 🌐 4. Chrome History

I first inspected Chrome's browsing history:

```bash
sqlite3 \
"C/Users/vera/AppData/Local/Google/Chrome/User Data/Default/History"
```

The history contained activity related to security research, including searches involving:

```text
Chrome CVEs
TryHackMe
Security research
```

This confirmed that the Chrome profile contained valuable forensic evidence.

---

# 🔑 5. Chrome Login Data

The next artifact was:

```text
Login Data
```

I opened the SQLite database:

```bash
sqlite3 \
"C/Users/vera/AppData/Local/Google/Chrome/User Data/Default/Login Data"
```

Then queried the credentials:

```sql
.headers on
.mode column

SELECT
    origin_url,
    action_url,
    username_value,
    hex(password_value) AS encrypted_password
FROM logins;
```

A relevant account appeared:

```text
Username: VeraSecretVault
```

The password was encrypted.

The password blob used Chrome's `v10` format.

That meant I needed to recover Chrome's encryption key.

---

# 🪟 6. Understanding the Encryption Chain

At this point the investigation became a chain of dependencies:

```text
Chrome Login Data
        ↓
Chrome AES Key
        ↓
Chrome Local State
        ↓
DPAPI
        ↓
DPAPI Master Key
        ↓
Windows Credential
```

The important realization was that Chrome's encryption could not be analyzed independently from Windows DPAPI.

---

# 🧩 7. DPAPI Master Key

The DPAPI files were located under:

```text
C/Users/vera/AppData/Roaming/Microsoft/Protect/
```

I searched the directory:

```bash
find C/Users/vera/AppData/Roaming/Microsoft/Protect \
  -type f -printf '%f %p\n'
```

The relevant SID was:

```text
S-1-5-21-2529683458-431225740-1723070931-1000
```

The master key identified during the investigation was:

```text
c90719ef-5b98-474e-b934-136d606a702a
```

---

# 🕵️ 8. Windows Registry Investigation

The following registry hives were available:

```text
C/Windows/System32/config/SAM
C/Windows/System32/config/SYSTEM
C/Windows/System32/config/SECURITY
```

I used Impacket to inspect the local secrets:

```bash
impacket-secretsdump \
  -sam C/Windows/System32/config/SAM \
  -system C/Windows/System32/config/SYSTEM \
  -security C/Windows/System32/config/SECURITY \
  LOCAL
```

The important discovery was an LSA `DefaultPassword`.

The recovered password was then used to decrypt the DPAPI master key.

> Sensitive credentials are intentionally redacted from the public repository.

---

# 🔓 9. DPAPI Decryption

With the recovered Windows credential, I used:

```bash
impacket-dpapi masterkey \
  -file '<MASTERKEY_PATH>' \
  -sid '<SID>' \
  -password '<RECOVERED_PASSWORD>'
```

The DPAPI master key was successfully decrypted.

This provided the cryptographic material required to continue into Chrome's encryption system.

---

# 🌐 10. Chrome Local State

Chrome stores its encrypted encryption key inside:

```text
Local State
```

I located the file using:

```bash
LOCAL_STATE="$(find "$PWD/C/Users/vera" \
  -type f -iname 'Local State' -print -quit)"

printf '%s\n' "$LOCAL_STATE"
```

The encrypted key was extracted with:

```bash
jq -r '.os_crypt.encrypted_key' "$LOCAL_STATE" |
base64 -d |
xxd
```

The DPAPI prefix was removed:

```bash
jq -r '.os_crypt.encrypted_key' "$LOCAL_STATE" |
base64 -d |
tail -c +6 > chrome-key.dpapi
```

The resulting DPAPI blob was decrypted using the previously recovered master key.

---

# 🔐 11. Chrome AES Key

The resulting Chrome key was stored locally for the next step.

I verified its size:

```bash
wc -c chrome-aes.key
```

The expected size was:

```text
32
```

This confirmed a 256-bit AES key.

---

# 🔑 12. Decrypting Chrome Credentials

Chrome `v10` / `v11` credentials use a structure containing:

```text
Version
Nonce
Ciphertext
Authentication Tag
```

The credential was decrypted using AES-256-GCM.

The result identified a credential associated with:

```text
https://vault.verasecret.com
```

and the username:

```text
VeraSecretVault
```

The recovered password was used to access the encrypted backup container.

Sensitive credential material is intentionally excluded from this repository.

---

# 🔒 13. Opening VeraCrypt

The encrypted container was opened using:

```bash
sudo cryptsetup tcryptOpen \
  --veracrypt \
  'C/Users/vera/Documents/backup' \
  vera_backup
```

The recovered credential was supplied when requested.

---

# 📁 14. Read-Only Mount

To preserve the evidence, I mounted the decrypted filesystem read-only:

```bash
sudo mkdir -p /mnt/vera

sudo mount -o ro \
  /dev/mapper/vera_backup \
  /mnt/vera
```

Then inspected the contents:

```bash
ls -la /mnt/vera
```

The mounted volume contained multiple documents, including the final PDF evidence.

---

# 🚩 15. Final Evidence

The final PDF contained the flag for the challenge.

```text
THM{1t_w4s_V3r4_A11_Al0ng?!}
```

---

# 🧠 Attack / Investigation Chain

The complete investigation can be represented as:

```text
                Windows Filesystem
                       │
          ┌────────────┴────────────┐
          │                         │
       Registry                  Chrome
          │                         │
 SAM/SYSTEM/SECURITY          Login Data
          │                         │
          ▼                         ▼
     LSA Secrets              Encrypted Password
          │                         │
          ▼                         │
   Windows Credential               │
          │                         │
          ▼                         │
     DPAPI Master Key               │
          │                         │
          ▼                         │
     Chrome Local State             │
          │                         │
          ▼                         │
      Chrome AES Key ───────────────┘
          │
          ▼
    VeraCrypt Password
          │
          ▼
   Encrypted Container
          │
          ▼
      Read-only Mount
          │
          ▼
          PDF
          │
          ▼
         FLAG
```

---

# 🧪 16. Custom Scripts

Two small Python scripts were used during the investigation.

### `decrypt_chrome_key.py`

Responsible for decrypting the Chrome DPAPI blob using the recovered master key.

### `decrypt_password.py`

Responsible for:

1. Opening the Chrome `Login Data` SQLite database.
2. Reading encrypted credentials.
3. Parsing the `v10/v11` format.
4. Extracting the nonce.
5. Decrypting the ciphertext with AES-256-GCM.
6. Printing the recovered credential.

The scripts are stored in:

```text
scripts/
```

---

# 📚 17. Alternative Techniques

Other tools could also assist with parts of this investigation:

* Hindsight — Chrome forensics
* Mimikatz — DPAPI analysis
* DonPAPI — DPAPI credential extraction
* RegRipper — Windows Registry analysis
* Volatility — Memory forensics
* Hashcat — Password recovery when applicable

These techniques are documented separately so the main investigation remains focused.

---

# 🛡️ 18. Defensive Lessons

This investigation demonstrates why Windows credential artifacts are valuable targets during forensic analysis.

### Registry Hives

Protect:

```text
SAM
SYSTEM
SECURITY
```

because offline access can expose sensitive authentication material.

### DPAPI

DPAPI-protected secrets can become accessible when the user's authentication material and master keys are recovered.

### Browser Credentials

Chrome's:

```text
Login Data
Local State
```

should be treated as sensitive forensic artifacts.

### VeraCrypt

Encrypted containers provide strong protection, but the security of the container ultimately depends on protecting the password.

### Monitoring

Organizations should monitor:

* Suspicious access to registry hives
* Credential-dumping tools
* Unexpected access to browser databases
* DPAPI-related activity
* Unauthorized encrypted-volume mounting

---

# 🧠 19. What I Learned

The biggest lesson from this challenge was that forensic investigation is about **correlation**.

At first, the important artifacts appeared unrelated:

```text
Registry
Chrome
DPAPI
VeraCrypt
PDF
```

But each artifact provided the information needed to investigate the next.

The investigation therefore became:

```text
Evidence
   ↓
Hypothesis
   ↓
Test
   ↓
New Evidence
   ↓
New Hypothesis
   ↓
Next Stage
```

The final flag was only the endpoint.

The real challenge was reconstructing the path that led to it.

---

# ⚠️ Disclaimer

This repository documents an authorized TryHackMe CTF/laboratory environment.

All techniques were performed against challenge-provided forensic artifacts.

Sensitive credentials, cryptographic keys, session material and other unnecessary secrets have been intentionally omitted or redacted.

This project is intended for educational and portfolio purposes.

---

## 👤 Author

**Victor Hugo**

Software Engineer | Cybersecurity | Offensive Security | Digital Forensics

Interested in:

* Cybersecurity
* Digital Forensics
* Windows Security
* Web Security
* Penetration Testing
* Incident Response
* Security Engineering

