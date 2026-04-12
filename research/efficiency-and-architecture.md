# Treasure-Hunter Research: Efficiency, Architecture & Unification

> How to make 15 grabber modules work as one fast, unified tool.

---

## Table of Contents

1. [Core Engineering Questions](#1-core-questions)
2. [Performance & Concurrency](#2-performance)
3. [Plugin Architecture](#3-plugin-architecture)
4. [Scan Profiles](#4-scan-profiles)
5. [Smart Path Prioritization](#5-prioritization)
6. [Streaming Output](#6-streaming-output)
7. [Error Resilience](#7-error-resilience)
8. [Build Pipeline](#8-build-pipeline)
9. [Testing Strategy](#9-testing)
10. [The Unification Layer](#10-unification)

---

## 1. Core Questions

Before building, these are the engineering decisions that determine whether treasure-hunter is a toy or a real tool:

| Question | Answer |
|----------|--------|
| How do 15 modules coordinate without stepping on each other? | Plugin architecture with shared event bus |
| What if one module crashes? | Isolated execution — catch exceptions per module, continue scanning |
| How fast can we scan? | Threading for I/O-bound file reads, `os.scandir()` for directory walking (5-50x faster than `os.walk` on Windows) |
| What about memory on huge directories? | Streaming — process files as discovered, don't buffer entire directory trees |
| How does operator control what runs? | Scan profiles (presets) + per-module enable/disable + TOML config |
| How do we handle time-limited physical access? | Smart prioritization — scan high-value paths first, `--timeout` auto-exits |
| How do findings flow from modules to the reporter? | Central findings queue — modules push, reporter pulls |
| Can we build on macOS for Windows targets? | No cross-compilation with Nuitka — use GitHub Actions CI/CD matrix |
| How do we test without a real Windows target? | Mock filesystem + registry fixtures + CI on Windows runner |
| How do we keep the binary small? | Modular imports — only load enabled modules + their deps |

---

## 2. Performance & Concurrency

### Directory Walking: `os.scandir()` (not `os.walk()`)

`os.scandir()` is 5-50x faster than naive `os.walk()` on Windows because it avoids redundant `stat()` calls. Windows' `FindFirstFile`/`FindNextFile` already returns file metadata — `os.scandir()` uses this directly.

**Real-world benchmark:** One developer saw directory walking drop from 90 seconds to 1.78 seconds on network shares.

Since Python 3.5, `os.walk()` internally uses `os.scandir()`, but building our own walker lets us:
- Apply cheap rules (extension, name) BEFORE expensive rules (content regex)
- Skip known-junk directories early (Windows\SxS, node_modules, .git objects)
- Yield files as discovered (streaming) instead of buffering

### Concurrency Model

```
Main Thread
  |
  +-- FileWalker (async generator, yields paths)
  |     |
  |     +-- applies cheap rules (extension, name, path) inline
  |     +-- skips excluded directories immediately
  |
  +-- ThreadPoolExecutor (N workers, default: 4)
  |     |
  |     +-- Worker 1: content scanning (regex, entropy)
  |     +-- Worker 2: content scanning
  |     +-- Worker 3: content scanning
  |     +-- Worker 4: content scanning
  |
  +-- GrabberModules (sequential per module, parallel across modules)
  |     |
  |     +-- Thread: CredGrabber
  |     +-- Thread: BrowserGrabber
  |     +-- Thread: WifiGrabber
  |     +-- Thread: CloudGrabber
  |     +-- ... (one thread per enabled module)
  |
  +-- FindingsQueue (thread-safe queue.Queue)
  |     |
  |     +-- All modules push findings here
  |
  +-- Reporter (consumes from queue, writes output)
```

### Why Threading (not asyncio, not multiprocessing)

| Model | Pros | Cons | Verdict |
|-------|------|------|---------|
| **Threading** | Simple, shared memory, good for I/O-bound file reads, works with pywin32/ctypes | GIL limits CPU parallelism | **Use this** — our bottleneck is I/O, not CPU |
| **asyncio** | Elegant for network I/O | Requires `aiofiles` for file I/O, doesn't help with pywin32/registry calls | Overkill — adds complexity for marginal gain on local file I/O |
| **multiprocessing** | True parallelism, bypasses GIL | Heavy — process spawn overhead, can't share pywin32 handles, complex IPC | Only useful if we add CPU-heavy analysis (ML classification) later |

### Cheap vs Expensive Rules (Snaffler's Key Insight)

This is the single most important performance optimization:

```
File discovered by walker
  |
  +-- [CHEAP] Check extension        → 0.001ms   → DISCARD or CONTINUE
  +-- [CHEAP] Check filename keywords → 0.001ms   → DISCARD or CONTINUE
  +-- [CHEAP] Check path patterns     → 0.001ms   → DISCARD or CONTINUE
  +-- [CHEAP] Check file size         → 0.001ms   → SKIP if > 50MB
  |
  +-- [EXPENSIVE] Read file content   → 1-100ms   → Only if cheap rules matched
  +-- [EXPENSIVE] Run content regex   → 1-50ms    → Only on text-like files
  +-- [EXPENSIVE] Calculate entropy   → 5-20ms    → Only on small suspicious files
```

Most files (~95%) are eliminated by cheap rules and never have their content read. This is how SauronEye scans 50,000 files in under a minute and Snaffler handles massive environments.

---

## 3. Plugin Architecture

### Module Interface (Base Class)

Every grabber module implements the same interface:

```python
from abc import ABC, abstractmethod
from queue import Queue
from treasure_hunter.models import Finding

class GrabberModule(ABC):
    """Base class for all grabber modules."""

    name: str                    # "BrowserGrabber"
    description: str             # "Extract saved browser credentials"
    requires_admin: bool         # False for most
    platforms: list[str]         # ["windows"]
    default_enabled: bool        # True

    @abstractmethod
    def run(self, context: ScanContext, findings_queue: Queue) -> None:
        """Execute this module's collection logic."""
        ...

    @abstractmethod
    def preflight_check(self) -> bool:
        """Quick check if this module can run (deps available, etc.)."""
        ...
```

### Module Discovery

Use `importlib` dynamic loading with a registration pattern:

```python
# treasure_hunter/grabbers/__init__.py
import importlib
import pkgutil

def discover_modules():
    """Auto-discover all grabber modules in this package."""
    modules = {}
    for importer, modname, ispkg in pkgutil.iter_modules(__path__):
        module = importlib.import_module(f".{modname}", __package__)
        for attr in dir(module):
            obj = getattr(module, attr)
            if isinstance(obj, type) and issubclass(obj, GrabberModule) and obj is not GrabberModule:
                modules[obj.name] = obj
    return modules
```

### Benefits

- Drop a new `.py` file in `grabbers/` → auto-discovered
- Community can contribute modules without touching core code
- Operator enables/disables per module in config
- Each module is independently testable
- Failed module doesn't take down the scan

---

## 4. Scan Profiles

Pre-built configurations for common engagement scenarios:

### Profile: `smash` (Fastest — 30 seconds)
**Use case:** Time-limited physical access, grab the highest-value stuff and go.

```toml
[profile.smash]
description = "Speed run — highest value targets only"
timeout = 30
modules = ["CredGrabber", "BrowserGrabber", "WifiGrabber", "CloudGrabber", "SessionGrabber"]
scan_paths = ["~/.ssh", "~/.aws", "~/.azure", "~/.kube", "~/Documents/*.kdbx"]
skip_content_scan = true
skip_entropy = true
```

### Profile: `triage` (Balanced — 2-5 minutes)
**Use case:** Standard red team engagement, good coverage without being slow.

```toml
[profile.triage]
description = "Balanced scan — credentials + high-value files"
timeout = 300
modules = ["CredGrabber", "BrowserGrabber", "WifiGrabber", "CloudGrabber",
           "SessionGrabber", "ChatGrabber", "CryptoGrabber", "FileGrabber"]
file_grabber_depth = 3          # max directory depth
max_file_size = "10MB"
content_scan = "high_value_only" # only scan files that matched cheap rules
```

### Profile: `full` (Comprehensive — 10-30 minutes)
**Use case:** Full audit of a target machine, no time pressure.

```toml
[profile.full]
description = "Full audit — every module, every path"
modules = ["all"]
content_scan = "all_text_files"
entropy_scan = true
network_scan = "mapped_only"
```

### Profile: `stealth` (Low footprint)
**Use case:** EDR-monitored environment, minimize detection.

```toml
[profile.stealth]
description = "Minimal footprint — avoid subprocess, no network"
modules = ["BrowserGrabber", "CloudGrabber", "ArtifactGrabber", "FileGrabber"]
no_subprocess = true            # pure Python only, no netsh/cmd
no_network = true               # skip network shares
sleep_between_reads = 50        # ms delay to avoid burst I/O detection
randomize_scan_order = true     # don't hit paths in predictable order
```

### CLI Usage

```bash
treasure-hunter.exe --profile smash --output E:\loot\
treasure-hunter.exe --profile full --encrypt-key operator.pub
treasure-hunter.exe --profile stealth --timeout 120
```

---

## 5. Smart Path Prioritization

When time is limited, scan the highest-value paths FIRST:

### Priority Queue (not alphabetical directory walk)

```
Priority 1 (scan first):
  ~/.ssh/
  ~/.aws/credentials
  ~/.azure/
  ~/.kube/config
  ~/.docker/config.json
  AppData/**/Login Data           (browser passwords)
  AppData/**/Cookies
  AppData/**/logins.json
  *.kdbx (KeePass files anywhere)
  *.pfx, *.pem, *.key

Priority 2 (scan second):
  AppData/**/Slack/
  AppData/**/discord/
  AppData/**/Teams/
  AppData/**/Outlook/*.pst
  Documents/*.rdp
  *.tfstate
  ConsoleHost_history.txt
  plum.sqlite (Sticky Notes)

Priority 3 (scan if time allows):
  Documents/**
  Desktop/**
  Downloads/**
  OneDrive/**
  Repos/Projects/Source/**

Priority 4 (scan last):
  C:\ full walk (everything else)
  Network shares
```

### Implementation

```python
import heapq

class PrioritizedScanner:
    def __init__(self):
        self.queue = []  # min-heap

    def add_path(self, path: str, priority: int):
        heapq.heappush(self.queue, (priority, path))

    def next_path(self) -> str:
        return heapq.heappop(self.queue)[1]
```

This means even if `--timeout 30` kills the scan early, we've already grabbed the most valuable stuff.

---

## 6. Streaming Output

Don't buffer all findings in memory — write them as discovered:

### JSON Lines Format (`.jsonl`)

Each finding is a complete JSON object on one line, written immediately:

```jsonl
{"id":"F001","severity":"CRITICAL","module":"CloudGrabber","title":"AWS keys in cleartext","path":"C:\\Users\\john\\.aws\\credentials","score":250}
{"id":"F002","severity":"HIGH","module":"BrowserGrabber","title":"Chrome saved passwords","path":"...\\Login Data","score":180}
{"id":"F003","severity":"MEDIUM","module":"FileGrabber","title":"SQL backup file","path":"C:\\Backups\\prod.sql.bak","score":95}
```

### Benefits

- Findings appear in real-time (operator can tail the output)
- Memory-efficient — no need to hold all findings in RAM
- Crash-resilient — partial results are still valid
- Post-processing friendly — `jq`, `grep`, pipe to other tools
- Final summary appended at scan completion

### Final Report Generation

At scan completion, read the `.jsonl` file and generate:
- Sorted JSON report (by score descending)
- CSV export
- HTML dashboard (optional)

---

## 7. Error Resilience

### Module Isolation

```python
for module in enabled_modules:
    try:
        module.run(context, findings_queue)
    except PermissionError as e:
        results.errors.append(f"{module.name}: Access denied — {e}")
    except Exception as e:
        results.errors.append(f"{module.name}: Failed — {e}")
        # Continue with next module — never crash the whole scan
```

### File-Level Resilience

```python
for entry in os.scandir(path):
    try:
        process_file(entry)
    except PermissionError:
        results.skipped_paths.append(entry.path)
    except (OSError, IOError):
        results.errors.append(f"Could not read: {entry.path}")
    # Never stop scanning because one file is locked/corrupted
```

### Timeout Enforcement

```python
import signal
import threading

def timeout_handler():
    """Force graceful shutdown when timeout expires."""
    findings_queue.put(SENTINEL)  # Signal reporter to finalize
    # Each module checks a shared Event flag
    shutdown_event.set()

if args.timeout:
    timer = threading.Timer(args.timeout, timeout_handler)
    timer.start()
```

---

## 8. Build Pipeline

### Nuitka Cannot Cross-Compile

Nuitka requires building on the target platform. You cannot build a Windows .exe from macOS.

### Solution: GitHub Actions CI/CD

```yaml
# .github/workflows/build.yml
name: Build Treasure-Hunter
on: [push, workflow_dispatch]

jobs:
  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install nuitka ordered-set
      - name: Build with Nuitka
        run: |
          python -m nuitka \
            --onefile \
            --standalone \
            --windows-console-mode=disable \
            --output-filename=treasure-hunter.exe \
            --include-package=treasure_hunter \
            treasure_hunter/__main__.py
      - uses: actions/upload-artifact@v4
        with:
          name: treasure-hunter-windows
          path: treasure-hunter.exe
```

### Dev Workflow

```
MacBook (dev)                    GitHub Actions              Target
    |                                |                         |
    +-- Write Python code            |                         |
    +-- Run tests locally            |                         |
    +-- git push -----------------> Build .exe (Nuitka)        |
    +-- Download artifact <--------- treasure-hunter.exe       |
    +-- Copy to USB ----------------------------------------> Run on target
```

### PyInstaller for Fast Dev Iteration

Use PyInstaller locally for quick testing (builds in seconds vs minutes for Nuitka):

```bash
# Fast dev build (macOS — just for testing logic, not for deployment)
pip install pyinstaller
pyinstaller --onefile treasure_hunter/__main__.py

# Production build (Windows CI — for actual deployment)
# Handled by GitHub Actions with Nuitka
```

---

## 9. Testing Strategy

### Unit Tests (per module)

```python
# tests/test_cloud_grabber.py
def test_finds_aws_credentials(tmp_path):
    """Create a fake .aws/credentials file and verify detection."""
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    creds_file = aws_dir / "credentials"
    creds_file.write_text("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

    grabber = CloudGrabber()
    findings = grabber.scan_path(tmp_path)

    assert len(findings) == 1
    assert findings[0].severity >= Severity.HIGH
    assert "AKIA" in findings[0].signals[0].matched_value
```

### Integration Tests

- Use `pytest` with `tmp_path` fixtures to create fake directory structures
- Mock Windows registry with `unittest.mock` for RegistryGrabber
- Test on actual Windows via GitHub Actions CI

### Test Fixtures

Create a `tests/fixtures/` directory with:
- Fake `.aws/credentials` files
- Fake Chrome `Login Data` SQLite DB (empty, just schema)
- Fake `.kdbx` file (empty, just magic bytes)
- Fake `ConsoleHost_history.txt` with sample commands
- Fake `credentials-config.json` (DBeaver format)

---

## 10. The Unification Layer

This is the answer to "what unifies it all" — the **ScanContext** object and **event-driven findings pipeline**:

### ScanContext (Shared State)

```python
@dataclass
class ScanContext:
    """Shared context passed to every module."""

    # Target info
    hostname: str
    domain: str
    username: str
    privilege_level: str          # "user" | "admin" | "system"
    os_version: str

    # Configuration
    config: Config                # Parsed TOML config
    profile: ScanProfile          # Active scan profile
    enabled_modules: list[str]

    # Runtime state
    scan_id: str
    started_at: datetime
    timeout_at: datetime | None
    shutdown_event: threading.Event  # Shared kill switch
    output_path: Path

    # Shared intelligence (modules feed each other)
    discovered_users: list[str]       # RegistryGrabber finds user profiles
    discovered_drives: list[str]      # NetworkGrabber finds mapped drives
    discovered_browsers: list[str]    # SoftwareGrabber finds installed browsers
    discovered_databases: list[str]   # SoftwareGrabber finds DB tools
```

### Why This Matters: Modules Feed Each Other

The unification isn't just running 15 modules side by side — it's that they **share intelligence**:

```
SoftwareGrabber runs first:
  -> discovers Chrome, Firefox, Edge installed
  -> discovers PuTTY, WinSCP, DBeaver installed
  -> writes to context.discovered_browsers, context.discovered_databases

BrowserGrabber reads context.discovered_browsers:
  -> only scans browsers that are actually installed
  -> skips Firefox if not present (faster)

SessionGrabber reads context.discovered_databases:
  -> only tries DBeaver extraction if DBeaver is installed
  -> skips HeidiSQL if not present

RegistryGrabber discovers user profiles:
  -> writes to context.discovered_users
  -> enables multi-user scanning for BrowserGrabber

NetworkGrabber discovers mapped drives:
  -> writes to context.discovered_drives
  -> FileGrabber includes network paths in its scan
```

### Findings Pipeline

```
Module --> Finding --> Queue --> Scorer --> StreamWriter --> Final Report
                                  |
                                  +-- Adds severity
                                  +-- Adds MITRE mapping
                                  +-- Deduplicates
                                  +-- Redacts sensitive values
```

### Deduplication

Same file can be flagged by multiple modules (FileGrabber finds `.kdbx` by extension, CredGrabber finds it by known path). Deduplicate by file path, merge signals:

```python
def merge_findings(existing: Finding, new: Finding) -> Finding:
    """Merge signals from multiple modules for the same file."""
    existing.signals.extend(new.signals)
    existing.total_score = sum(s.score for s in existing.signals)
    existing.severity = compute_severity(existing.total_score)
    return existing
```

### Execution Order

Modules run in dependency order, not alphabetically:

```
Phase 1 (Recon — feeds everything else):
  SoftwareGrabber  → discovers what's installed
  RegistryGrabber  → discovers user profiles, MRU, USB history
  NetworkGrabber   → discovers mapped drives

Phase 2 (Targeted grabs — use Phase 1 intel):
  CredGrabber      → LaZagne credential harvest
  BrowserGrabber   → browser passwords/cookies (only installed browsers)
  WifiGrabber      → stored WiFi passwords
  CloudGrabber     → cloud CLI tokens
  SessionGrabber   → PuTTY/WinSCP/DBeaver (only installed tools)
  DevToolGrabber   → git/npm/pip tokens
  ChatGrabber      → Slack/Discord/Teams
  CryptoGrabber    → wallet files
  CertGrabber      → certificate store
  WSLGrabber       → WSL filesystem
  ArtifactGrabber  → PS history, sticky notes, clipboard

Phase 3 (File sweep — broadest, slowest):
  FileGrabber      → full filesystem scan with classifier rules
```

This ordering means the fast targeted grabs happen first (Phase 1+2 take ~10 seconds), and the slow filesystem sweep is Phase 3. If `--timeout` fires, we already have the best stuff.

---

## Summary: What Makes It a Unified Tool (Not 15 Scripts Taped Together)

| Feature | How It Unifies |
|---------|---------------|
| **ScanContext** | Shared state — modules discover intelligence that other modules consume |
| **Execution phases** | Recon first, targeted grabs second, broad sweep last |
| **Findings pipeline** | Single queue — all modules push findings in the same format |
| **Deduplication** | Same file from multiple modules = merged signals, higher score |
| **Scoring engine** | One consistent scoring system across all 15 modules |
| **Scan profiles** | One flag (`--profile smash`) configures all modules coherently |
| **Timeout enforcement** | Shared kill switch — graceful shutdown preserves partial results |
| **Streaming output** | JSONL written in real-time — crash-resilient, operator can watch live |
| **Plugin architecture** | Uniform interface — add/remove modules without touching core |
| **Priority scanning** | High-value paths first — even partial scans are useful |
| **MITRE ATT&CK mapping** | Every finding from every module maps to the same framework |
| **Single .exe** | Everything compiles to one binary — no "install these 5 tools" |
