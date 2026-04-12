# Treasure-Hunter Research: Deep Dive

> Extended research — OPSEC, privilege levels, application creds, forensic footprint, reporting, and more.

---

## Table of Contents

1. [Privilege Levels — What We Can Grab Without Admin](#1-privilege-levels)
2. [Application Credential Stores](#2-application-credential-stores)
3. [Developer Tool Credentials](#3-developer-tool-credentials)
4. [Virtual Machine Secrets](#4-virtual-machine-secrets)
5. [Mobile Device Data](#5-mobile-device-data)
6. [Password Manager Local Caches](#6-password-manager-local-caches)
7. [OPSEC & Evasion](#7-opsec--evasion)
8. [Forensic Footprint & Cleanup](#8-forensic-footprint--cleanup)
9. [Output Encryption & Secure Exfil](#9-output-encryption)
10. [Reporting Best Practices](#10-reporting)
11. [Network Drive Access](#11-network-drives)
12. [Updated Module List](#12-updated-module-list)
13. [Sources](#13-sources)

---

## 1. Privilege Levels

Not everything requires admin. Here's what treasure-hunter can grab at each privilege level:

### No Admin Required (Standard User Context)

These work because DPAPI decrypts in the current user's context automatically:

| Target | Method |
|--------|--------|
| Browser saved passwords (Chrome, Edge, Firefox) | DPAPI CryptUnprotectData in user context |
| Browser cookies & history | SQLite DB read |
| WiFi passwords | `netsh wlan show profiles key=clear` |
| Windows Credential Manager (user vault) | DPAPI in user context |
| RDP saved connections | Registry HKCU |
| Outlook PST/OST files | Direct file read |
| Slack/Discord/Teams tokens | LevelDB / AppData read |
| AWS/Azure/GCP/k8s/Docker tokens | File read from user profile |
| Crypto wallet files | AppData read |
| SSH keys (~/.ssh) | File read |
| Git credentials | `.git-credentials` file read |
| PowerShell history | File read |
| Sticky Notes | SQLite DB read |
| Clipboard history | SQLite DB read |
| Recent documents / LNK files | File read |
| Mapped network drives | `win32net.NetUseEnum` |
| KeePass databases (find, not decrypt) | File discovery |
| PuTTY saved sessions | Registry HKCU |
| WinSCP saved passwords | Registry HKCU + WinSCP.ini |
| FileZilla saved passwords | `%AppData%\FileZilla\recentservers.xml` (base64, trivial decode) |
| DBeaver saved passwords | `credentials-config.json` (AES-128-CBC with hardcoded key) |
| HeidiSQL saved passwords | Registry (custom weak encryption) |
| All file scanning & classification | Standard file reads |
| Entropy analysis | Standard file reads |
| WSL filesystem access | File read (ext4.vhdx) |
| Installed software enumeration | Registry HKLM (read access) |
| Cloud sync folder scanning | File read (OneDrive, Dropbox, etc.) |

### Requires Local Admin

| Target | Method |
|--------|--------|
| SAM database (local user hashes) | Registry HKLM\SAM |
| LSA secrets | Registry HKLM\SECURITY |
| DPAPI machine masterkeys | DPAPI_SYSTEM from LSA |
| Other users' DPAPI blobs | Access to their profile directories |
| Windows Certificate Store (machine certs) | certutil as admin |
| LSASS memory dump | Process memory read |
| Event log manipulation | Requires admin |
| Print spool files | `%SystemRoot%\System32\spool\PRINTERS\` |
| Service account credentials | Registry HKLM |

### Requires Domain Admin

| Target | Method |
|--------|--------|
| Domain DPAPI backup key | LSASS on Domain Controller |
| Decrypt ALL users' DPAPI blobs | Using domain backup key |
| NTDS.dit (all domain hashes) | Volume Shadow Copy on DC |
| AD-wide SMB share sweep | LDAP enumeration + SMB auth |

**Key insight:** The vast majority of our 13+ grabber modules work without admin. We should design treasure-hunter to run at whatever privilege level it gets and report what it found, rather than requiring elevation.

---

## 2. Application Credential Stores

### Remote Access Tools (Module: SessionGrabber)

[SessionGopher](https://github.com/Arvanaghi/SessionGopher) already does this in PowerShell. We port to Python:

| Application | Storage Location | Encryption |
|-------------|-----------------|------------|
| **PuTTY** | `HKCU\Software\SimonTatham\PuTTY\Sessions\` | None — plaintext hostnames, usernames. Private keys at path in `PublicKeyFile` |
| **WinSCP** | `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\` OR `WinSCP.ini` | Custom weak encryption — trivially reversible |
| **FileZilla** | `%AppData%\FileZilla\recentservers.xml` + `sitemanager.xml` | Base64 encoded (not encrypted) |
| **SuperPuTTY** | `%AppData%\SuperPuTTY\Sessions.xml` | Plaintext XML |
| **mRemoteNG** | `%AppData%\mRemoteNG\confCons.xml` | AES-128-CBC with hardcoded default password "mR3m" |
| **MobaXterm** | `HKCU\Software\Mobatek\MobaXterm\` | Custom encryption — decryptable with known algorithm |
| **RDP files** | `*.rdp` across Desktop/Documents | Plaintext (hostname, username) — password DPAPI-encrypted if saved |
| **RDP cached creds** | `HKCU\Software\Microsoft\Terminal Server Client\Servers\` | Registry — server hostnames with username hints |
| **Royal TS** | `*.rtsz` files | AES encrypted but often with weak/default passwords |

### Database Management Tools

| Application | Storage Location | Encryption |
|-------------|-----------------|------------|
| **DBeaver** | `%AppData%\DBeaverData\workspace6\General\.dbeaver\credentials-config.json` | AES-128-CBC with **hardcoded key** `babb4a9f774ab853c96c2d653dfe544a` and zero IV — trivially decryptable |
| **HeidiSQL** | `HKCU\Software\HeidiSQL\Servers\` | Custom weak encryption — Metasploit module exists |
| **SSMS (SQL Server)** | Recent connections in MRU, saved in `SqlStudio.bin` | Mixed — some plaintext, some DPAPI |
| **Azure Data Studio** | `%AppData%\azuredatastudio\User\settings.json` | May contain connection strings |
| **Navicat** | `HKCU\Software\PremiumSoft\Navicat\Servers\` | Blowfish with known key |
| **DataGrip** | `%AppData%\JetBrains\DataGrip*\options\security.xml` | KeePass-style master password or plaintext |
| **pgAdmin** | `%AppData%\pgAdmin\pgadmin4.db` | SQLite with stored server connections |

---

## 3. Developer Tool Credentials

| Tool | Location | What's There |
|------|----------|-------------|
| **Git Credential Manager** | Windows Credential Manager (generic credentials starting with `git:`) | GitHub/GitLab/Azure DevOps tokens |
| **Git credentials file** | `%USERPROFILE%\.git-credentials` | Plaintext `https://user:token@github.com` |
| **Git config** | `%USERPROFILE%\.gitconfig` | May contain username, email, credential helper config |
| **npm tokens** | `%USERPROFILE%\.npmrc` | Auth tokens for npm registries |
| **pip/PyPI** | `%USERPROFILE%\.pypirc` + `%AppData%\pip\pip.conf` | PyPI upload credentials |
| **NuGet** | `%AppData%\NuGet\NuGet.Config` | API keys for NuGet feeds |
| **Maven** | `%USERPROFILE%\.m2\settings.xml` | Repository credentials |
| **Gradle** | `%USERPROFILE%\.gradle\gradle.properties` | Repository credentials, signing keys |
| **Cargo (Rust)** | `%USERPROFILE%\.cargo\credentials.toml` | crates.io token |
| **VS Code settings** | `%AppData%\Code\User\settings.json` | May contain tokens, connection strings, API keys in settings |
| **VS Code extensions** | `%USERPROFILE%\.vscode\extensions\` | Extension auth data |
| **JetBrains IDEs** | `%AppData%\JetBrains\*\options\` | Stored credentials, recent projects |
| **Postman** | `%AppData%\Postman\` | API collections with auth tokens, environment variables with secrets |
| **Insomnia** | `%AppData%\Insomnia\` | Same as Postman — API auth data |

---

## 4. Virtual Machine Secrets

| Target | Location | Notes |
|--------|----------|-------|
| **VMware Workstation encryption** | Windows Credential Manager + `.vmx` files | Encryption password stored in Credential Manager; decryptable with hardcoded key from `vmwarebase.dll` |
| **VMware saved connections** | `ace.dat` file | ESXi/vSphere credentials — PBKDF2-HMAC-SHA-1 encrypted with known key derivation |
| **VirtualBox** | `%USERPROFILE%\VirtualBox VMs\*.vbox` | VM configs — may reference shared folders, network configs |
| **Hyper-V** | `%ProgramData%\Microsoft\Windows\Hyper-V\` | VM configs with network settings |
| **VMkatz** | VM memory snapshots (`.vmem`, `.vmss`) | [VMkatz](https://github.com/nikaiw/VMkatz) extracts Windows credentials directly from VM memory |
| **VM shared folders** | Inside `.vmx` / `.vbox` configs | May expose host filesystem paths |

---

## 5. Mobile Device Data

| Target | Location | What's There |
|--------|----------|-------------|
| **iTunes iPhone backups** | `%AppData%\Apple Computer\MobileSync\Backup\` | Full device backups — contacts, messages, photos, app data, WiFi passwords, keychain (if unencrypted backup) |
| **Android backups** | `%USERPROFILE%\` (various) | ADB backup files if developer |
| **Phone Link / Your Phone** | `%LocalAppData%\Packages\Microsoft.YourPhone_*\LocalCache\` | Synced photos, messages, notifications |

---

## 6. Password Manager Local Caches

These are encrypted but finding them is intelligence value (confirms what the target uses):

| Manager | Location | Notes |
|---------|----------|-------|
| **KeePass** | `*.kdbx` anywhere (common: Documents, Desktop, OneDrive) | Encrypted — but finding it + keyfile is valuable recon |
| **1Password** | `%LocalAppData%\1Password\` | Local vault cache, encrypted with master password |
| **Bitwarden** | `%AppData%\Bitwarden\` | Encrypted vault cache — offline access for 30 days |
| **LastPass** | Browser extension data in Chrome/Edge/Firefox extension dirs | Local encrypted vault cache |
| **Dashlane** | `%AppData%\Dashlane\` | Encrypted local cache |
| **KeePassXC** | `*.kdbx` files | Same as KeePass |
| **Enpass** | `%AppData%\Enpass\` + cloud sync | SQLCipher encrypted database |

**Strategy:** Don't try to decrypt these — just flag them as CRITICAL findings. The location of a password manager vault is high-value intel for a red team report.

---

## 7. OPSEC & Evasion

### AV/EDR Considerations

| Technique | Description | Priority |
|-----------|-------------|----------|
| **Nuitka compilation** | Compiles to native C — drastically lower AV detection vs PyInstaller | **Must-have** |
| **No PowerShell** | Avoid PowerShell entirely — heavily monitored by AMSI, Script Block Logging, ETW | **Must-have** |
| **Pure Python / native API** | Use ctypes/pywin32 for Windows API calls instead of shelling out to cmd | **Should-have** |
| **Minimize process creation** | Every `subprocess.run()` creates a child process visible in event logs (Event 4688) | **Should-have** |
| **Memory-only operation** | Read files into memory, process, discard — avoid writing temp files | **Should-have** |
| **String obfuscation** | Avoid plaintext strings like "password", "credential" in the binary | **Nice-to-have** |
| **Timestomping** | Modify file timestamps to blend in if writing output files | **Nice-to-have** |

### What NOT to Do

| Anti-Pattern | Why |
|-------------|-----|
| Shell out to `netsh`, `reg query`, `wmic` | Creates child processes logged in Event 4688 + Prefetch |
| Use PowerShell for anything | AMSI + Script Block Logging + ETW = instant detection |
| Touch LSASS without need | EDR kernel callbacks trigger immediately |
| Write files to `%TEMP%` | Heavily monitored directory |
| Clear event logs | Event 1102 = instant red flag |

### Recommended Approach

Use native Python + ctypes/pywin32 for everything possible:
- Registry reads → `winreg` stdlib (no subprocess)
- File metadata → `os.stat()` + `pywin32` for owner/ACL
- WiFi passwords → Parse XML from `netsh` output (one subprocess, unavoidable)
- Network shares → `win32net.NetUseEnum()` (no subprocess)
- Browser DBs → Direct SQLite reads with `sqlite3` stdlib

---

## 8. Forensic Footprint & Cleanup

### What Treasure-Hunter Will Leave Behind

| Artifact | Location | Mitigation |
|----------|----------|------------|
| **Prefetch file** | `%SystemRoot%\Prefetch\TREASURE-HUNTER.EXE-*.pf` | Rename binary to something benign (e.g., `svchost_update.exe`); delete Prefetch entry on cleanup |
| **Event 4688** (process creation) | Security event log | Unavoidable — minimize child processes; use innocuous binary name |
| **MFT entry** | NTFS Master File Table | Exists even if file deleted; use `--no-write` mode to avoid creating output files on target |
| **ShimCache / AmCache** | Registry | Records executable metadata; cleaning requires admin + specific registry edits |
| **USB connection logs** | `HKLM\SYSTEM\CurrentControlSet\Enum\USB\` + `setupapi.dev.log` | Unavoidable if using USB deployment |
| **Recent files** | LNK files if output opened | Avoid opening output on target; exfil directly to USB |
| **UserAssist** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` | Records GUI program execution; use CLI-only mode |

### Cleanup Capabilities (`--cleanup` flag)

| Action | Admin Required | Risk |
|--------|---------------|------|
| Delete output files from target | No | Low |
| Delete Prefetch entry | Yes | Medium — deletion itself may be logged |
| Clear specific Event Log entries | Yes | High — selective deletion is suspicious |
| Timestomp modified files | No | Low |
| Delete temp files | No | Low |

**Recommendation:** Run with `--output` pointing to USB drive or remote share. Avoid writing anything to the local target disk. The `--cleanup` flag should only delete files we created, never touch system logs.

---

## 9. Output Encryption

### Encrypt the Loot Report

The report should be encrypted before it's written anywhere — if the USB is found, the data is protected:

| Method | Implementation |
|--------|---------------|
| **AES-256-GCM** | Generate random session key → encrypt report → wrap session key with RSA public key → output single encrypted blob |
| **Operator's public key** | Operator pre-loads their RSA public key in `config.toml` — only they can decrypt the report |
| **Password-based** | `--encrypt-password <pass>` → PBKDF2 key derivation → AES-256-GCM |

### Output Formats

| Format | Use Case |
|--------|----------|
| **JSON** (default) | Machine-readable, easy to parse in post-processing pipelines |
| **CSV** | Quick triage in Excel — one row per finding |
| **HTML** (single file) | Self-contained interactive report with sortable tables, severity color coding |
| **Encrypted blob** | AES-256-GCM wrapped report — any format inside |

### Report Structure

```json
{
  "scan_id": "th-20260408-143022",
  "target": {
    "hostname": "DESKTOP-ABC123",
    "domain": "CORP.LOCAL",
    "username": "john.smith",
    "privilege_level": "user",
    "os_version": "Windows 11 23H2"
  },
  "scan_config": {
    "modules_enabled": ["all"],
    "started_at": "2026-04-08T14:30:22Z",
    "completed_at": "2026-04-08T14:31:45Z",
    "duration_seconds": 83
  },
  "stats": {
    "files_scanned": 142385,
    "dirs_scanned": 8291,
    "findings_total": 47,
    "findings_critical": 3,
    "findings_high": 8,
    "findings_medium": 15,
    "findings_low": 12,
    "findings_info": 9
  },
  "findings": [
    {
      "id": "F001",
      "severity": "CRITICAL",
      "score": 250,
      "category": "credentials",
      "module": "CloudGrabber",
      "title": "AWS Access Keys in cleartext",
      "file_path": "C:\\Users\\john.smith\\.aws\\credentials",
      "signals": [
        {"type": "path_match", "detail": ".aws\\credentials", "score": 50},
        {"type": "content_match", "detail": "AKIA[REDACTED]", "score": 100},
        {"type": "extension_match", "detail": "credentials file", "score": 50},
        {"type": "keyword_match", "detail": "aws_secret_access_key", "score": 50}
      ],
      "mitre_attack": ["T1552.001"],
      "content_snippet": "aws_access_key_id = AKIA***[REDACTED]***",
      "metadata": {
        "size_bytes": 284,
        "modified": "2026-03-15T09:22:11Z",
        "owner": "CORP\\john.smith"
      }
    }
  ],
  "credentials_harvested": {
    "browser_passwords": 23,
    "wifi_passwords": 4,
    "cloud_tokens": 2,
    "saved_sessions": 7,
    "total": 36
  },
  "errors": [],
  "skipped_paths": []
}
```

### MITRE ATT&CK Mapping

Every finding maps to relevant ATT&CK techniques:

| Finding Type | MITRE Technique |
|-------------|-----------------|
| Credentials in files | T1552.001 — Credentials In Files |
| Browser passwords | T1555.003 — Credentials from Web Browsers |
| WiFi passwords | T1552.002 — Credentials in Registry |
| Cloud tokens | T1552.001 — Credentials In Files |
| DPAPI secrets | T1555.004 — Windows Credential Manager |
| Sensitive documents | T1005 — Data from Local System |
| Network share files | T1039 — Data from Network Shared Drive |
| Archive/backup files | T1005 — Data from Local System |
| Crypto wallets | T1005 — Data from Local System |

---

## 10. Reporting

### Red Team Report Integration

Treasure-hunter output should feed directly into standard red team report templates:

| Section | What We Provide |
|---------|----------------|
| **Executive Summary** | Stats: X critical findings, Y credentials harvested, Z documents flagged |
| **Technical Findings** | Each finding with severity, MITRE mapping, evidence snippet, remediation |
| **Credential Exposure** | All harvested credentials categorized by type and risk |
| **Data Exposure** | Sensitive documents and files found with classification |
| **Attack Path** | How harvested credentials enable lateral movement |
| **Remediation** | Prioritized list based on severity scores |

Reference: [Red Team Report Template](https://redteam.guide/docs/Templates/report_template/)

---

## 11. Network Drives

### Three Access Levels

| Mode | CLI Flag | How It Works | Noise Level |
|------|----------|-------------|-------------|
| **Mapped only** | `--network-mapped-only` | Scan drives already mounted (Z:\, S:\, etc.) via `win32net.NetUseEnum()` | Silent — no network traffic |
| **Discover shares** | `--network-discover` | Enumerate SMB shares on known/nearby hosts | Moderate — SMB traffic visible |
| **AD sweep** | `--network-ad-sweep` | LDAP query for all domain computers → enumerate all shares → scan | Loud — lots of LDAP + SMB |
| **Specific targets** | `--shares \\srv\share` | Operator-specified UNC paths | Targeted |

### Key Tools

| Tool | Use |
|------|-----|
| [snaffler-ng](https://pypi.org/project/snaffler-ng/) | Pip-installable, works as Python library, SMB + FTP + local scanning |
| [snafflepy](https://github.com/cisagov/snafflepy) | LDAP AD discovery + SMB enum + TOML rules |
| [impacket](https://github.com/fortra/impacket) | SMB client with pass-the-hash and Kerberos support |
| [smbprotocol](https://pypi.org/project/smbprotocol/) | Pure Python SMB2/3 library |

---

## 12. Updated Module List

Final count: **15 grabber modules**

| # | Module | Privilege | Source/Dependency |
|---|--------|-----------|-------------------|
| 1 | **FileGrabber** | User | snafflepy/snaffler-ng classifiers |
| 2 | **CredGrabber** | User (admin for SAM/LSA) | LaZagne + pypykatz |
| 3 | **BrowserGrabber** | User | DPAPI + SQLite |
| 4 | **WifiGrabber** | User | netsh subprocess |
| 5 | **RegistryGrabber** | User (admin for HKLM\SAM) | winreg + python-registry |
| 6 | **ArtifactGrabber** | User | PS history, sticky notes, clipboard, RDP cache, thumbnails |
| 7 | **ChatGrabber** | User | Slack/Discord/Teams LevelDB + AppData |
| 8 | **CloudGrabber** | User | AWS/Azure/GCP/k8s/Docker file reads |
| 9 | **CryptoGrabber** | User | Known wallet paths |
| 10 | **WSLGrabber** | User | ext4.vhdx access |
| 11 | **CertGrabber** | User (admin for machine store) | wincertstore + DPAPI |
| 12 | **SoftwareGrabber** | User | winreg enumeration |
| 13 | **NetworkGrabber** | User | snaffler-ng + impacket for SMB shares |
| 14 | **SessionGrabber** NEW | User | PuTTY/WinSCP/FileZilla/mRemoteNG/MobaXterm/RDP/DBeaver/HeidiSQL |
| 15 | **DevToolGrabber** NEW | User | Git creds, npm tokens, pip/pypirc, NuGet, Postman, IDE configs, VM configs |

---

## 13. Sources

### Application Credentials
- [SessionGopher](https://github.com/Arvanaghi/SessionGopher) — PuTTY/WinSCP/FileZilla/SuperPuTTY/RDP extraction
- [WinSCPPasswdExtractor](https://github.com/NeffIsBack/WinSCPPasswdExtractor) — WinSCP credential extraction
- [DBeaver password decryption](https://simonsc.medium.com/how-to-extract-saved-passwords-from-dbeaver-1cbc8aea6f5d)
- [HeidiSQL password recovery](https://gist.github.com/jpatters/4553139)
- [VM-Password-Extractor](https://github.com/archidote/VM-Password-Extractor) — VMware/VirtualBox encryption
- [VMkatz](https://github.com/nikaiw/VMkatz) — Extract creds from VM memory
- [pyvmx-cracker](https://github.com/axcheron/pyvmx-cracker) — VMware VMX password cracking

### OPSEC & Evasion
- [AMSI Bypass in 2025](https://medium.com/@thesecguy/amsi-bypass-in-2025-bypassing-modern-av-edr-f8a46b91280e)
- [AMSI and ETW bypassing](https://blog.silent4business.com/en/2026/02/05/advanced-evasion-in-windows-disabling-amsi-and-etw-via-powershell/)
- [CrowdStrike patchless AMSI bypass](https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/)
- [AV Bypass techniques](https://www.verylazytech.com/windows/antivirus-av-bypass)
- [Red Team OPSEC & Anti-Forensics](https://medium.com/30-days-of-red-team/30-days-of-red-team-day-13-operational-security-anti-forensics-728df45a09e6)

### Forensic Footprint
- [Hunting Red Team Activities with Forensic Artifacts](https://www.exploit-db.com/docs/48498)
- [HackTricks Windows Forensics](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics)
- [Investigating data exfiltration artifacts](https://www.magnetforensics.com/blog/investigating-data-exfiltration-key-digital-artifacts-across-windows-linux-and-macos/)

### Privilege & DPAPI
- [Abusing DPAPI](https://z3r0th.medium.com/abusing-dpapi-40b76d3ff5eb)
- [DPAPI Extracting Passwords — HackTricks](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords)
- [Windows DPAPI — Internal All The Things](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-dpapi/)
- [Windows secrets extraction summary](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary)

### Reporting
- [Red Team Report Template](https://redteam.guide/docs/Templates/report_template/)
- [Red Team Reporting Toolkit](https://medium.verylazytech.com/red-team-reporting-toolkit-10-templates-tools-master-professional-pentest-reports-step-by-step-658a5db7941d)

### Network Drives
- [snaffler-ng (PyPI)](https://pypi.org/project/snaffler-ng/)
- [snafflepy (CISA)](https://github.com/cisagov/snafflepy)
- [Credential Hunting on Network Shares](https://routezero.security/2025/06/07/credential-hunting-on-network-shares-a-classic-that-still-hits-hard/)
- [impacket smbclient](https://github.com/fortra/impacket/blob/master/impacket/examples/smbclient.py)
