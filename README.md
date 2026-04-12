# Treasure Hunter

Red team file discovery and credential extraction tool. Scans target systems for valuable files — passwords, tokens, keys, configs, documents — using intelligent scoring, then extracts the actual credential data from discovered artifacts.

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

# Scan-only mode (no credential extraction)
treasure-hunter --no-grabbers

# Run specific grabber modules only
treasure-hunter --grabbers cloud_cred git_cred browser
```

## What It Does

Treasure Hunter operates in two layers:

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
├── cli.py                  # CLI with 4 scan profiles
├── scanner.py              # Three-phase scan engine (Recon → Targeted → Grab → Sweep)
├── models.py               # Finding, Signal, ScanResult data models
├── entropy.py              # Shannon entropy for secret detection
├── reporter.py             # Real-time JSONL streaming output
├── rules/
│   └── value_taxonomy.py   # 6 categories, 533 detection patterns
└── grabbers/               # 15 credential extraction modules
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

- **Zero network connections** — all analysis is local
- **Minimal disk writes** — only JSONL output file
- **No subprocess calls** — pure Python + ctypes (no PowerShell, no cmd)
- **Graceful failures** — every module catches its own exceptions
- **Copy-then-read** for locked SQLite DBs (Chrome, Firefox)
- **Configurable thread limits** to avoid CPU spikes
- **Process memory scanning disabled by default** (highest EDR risk)

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

189 tests covering scanner engine, entropy analysis, value taxonomy, grabber framework, and individual module parsers.

## Building for Deployment

```bash
# Nuitka (recommended — better AV evasion)
pip install nuitka
nuitka --standalone --onefile treasure_hunter/__main__.py -o treasure-hunter.exe

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

## License

For authorized security testing, red team engagements, and educational purposes only.
