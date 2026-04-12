# TREASURE-HUNTER Implementation Complete

🏴‍☠️ **Red team file discovery tool with intelligent value scoring**

## Quick Start

```bash
# Install dependencies
pip install -e .

# Quick 5-minute scan (default)
python3 -m treasure_hunter

# Full comprehensive scan
python3 -m treasure_hunter -p full

# Target specific directory
python3 -m treasure_hunter -t /path/to/scan

# Stealth scan with minimal system impact
python3 -m treasure_hunter -p stealth -o stealth_results.jsonl
```

## Architecture Overview

### Core Components

1. **Value Taxonomy** (`treasure_hunter/rules/value_taxonomy.py`)
   - 6 categories with weighted scoring (CREDENTIALS=5, INFRASTRUCTURE=4, etc.)
   - 400+ file extensions, keywords, path patterns, and content regex
   - Windows-focused with corporate environment emphasis

2. **Scanner Engine** (`treasure_hunter/scanner.py`)
   - Three-phase execution: Recon → Targeted → Sweep
   - Multi-threaded with configurable pool sizes
   - Priority queue for time-limited engagements
   - Graceful error handling for OPSEC

3. **CLI Interface** (`treasure_hunter/cli.py`)
   - 4 scan profiles: smash, triage, full, stealth
   - JSONL streaming output for crash resilience
   - Platform-appropriate default targets

4. **Data Models** (`treasure_hunter/models.py`)
   - Structured findings with severity levels
   - Additive scoring system (signals stack)
   - Rich metadata extraction

### Three-Phase Scan Strategy

**Phase 1: RECON** (< 30 seconds)
- Fast metadata sweep using `os.scandir()`
- Build priority queues based on extension/path patterns
- No content analysis - pure filesystem metadata

**Phase 2: TARGETED** (Profile-dependent)
- Analyze high-priority files first (credentials, recent files)
- Parallel processing with thread pool
- Content pattern matching for high-value files
- Early termination if time limit reached

**Phase 3: SWEEP** (Remaining time)
- Comprehensive scan of all remaining locations
- Lower priority files analyzed if time permits
- Fills gaps missed by priority targeting

### Scan Profiles

| Profile  | Duration | Threads | Use Case |
|----------|----------|---------|----------|
| **smash**   | 5 min    | 16      | Quick smash-and-grab |
| **triage**  | 30 min   | 12      | Operational planning |
| **full**    | 2+ hours | 8       | Intelligence gathering |
| **stealth** | 8+ hours | 2       | Low-profile persistence |

## Value Categories

### 1. CREDENTIALS & SECRETS (Weight: 5)
- **Extensions**: `.kdbx`, `.pem`, `.key`, `.env`, `.pfx`, `.gpg`
- **Keywords**: `password`, `credential`, `secret`, `api_key`, `private`
- **Paths**: `*\AppData\Roaming\Microsoft\Credentials\*`, `*\.ssh\*`
- **Content**: AWS keys, private keys, connection strings

### 2. INFRASTRUCTURE INTEL (Weight: 4) 
- **Extensions**: `.rdp`, `.ovpn`, `.conf`, `.tf`, `.yml`
- **Keywords**: `vpn`, `firewall`, `network`, `ansible`, `ldap`
- **Content**: Private IP ranges, LDAP URLs, SMB paths

### 3. SENSITIVE DOCUMENTS (Weight: 3)
- **Extensions**: `.docx`, `.pdf`, `.pst`, `.xlsx`
- **Keywords**: `financial`, `ssn`, `legal`, `confidential`, `board`
- **Content**: SSNs, credit cards, confidentiality markers

### 4. SOURCE CODE & IP (Weight: 3)
- **Extensions**: `.cs`, `.py`, `.sln`, `.fig`, `.dwg`
- **Keywords**: `prototype`, `proprietary`, `patent_pending`
- **Content**: Copyright notices, proprietary licenses

### 5. UNRELEASED SOFTWARE (Weight: 4)
- **Extensions**: `.exe`, `.msi`, `.apk`, `.iso`, `.firmware`
- **Keywords**: `beta`, `pre-release`, `internal_build`, `canary`
- **Paths**: `*\Builds\*`, `*\Releases\*`, `*\Internal\*`

### 6. BACKUPS & ARCHIVES (Weight: 4)
- **Extensions**: `.zip`, `.sql`, `.bak`, `.sqlite`, `.vmdk`
- **Keywords**: `backup`, `dump`, `archive`, `migration`
- **Content**: SQL dump markers, database schemas

## Scoring System

**Base Scoring:**
- Extension match: `category_weight × 15`
- Keyword match: `category_weight × 12` 
- Path pattern: `category_weight × 20`
- Content pattern: `category_weight × 10`
- Recency bonus: `+10-15` (files modified in last 30 days)

**Severity Thresholds:**
- **CRITICAL**: 200+ (immediate exploit potential)
- **HIGH**: 120+ (high operational value)
- **MEDIUM**: 60+ (moderate interest)
- **LOW**: 25+ (worth noting)

**Example Scoring:**
```
admin-passwords.kdbx (modified yesterday):
- Extension (.kdbx): 5 × 15 = 75 pts
- Keyword (passwords): 5 × 12 = 60 pts  
- Recency (< 7 days): +15 pts
- Total: 150 pts → HIGH severity
```

## OPSEC Considerations

### Minimal Footprint
- **No writes** except JSONL output file
- **No network** connections or external dependencies
- **Memory efficient** with streaming processing
- **Graceful errors** - never crash on access denied

### Performance Optimizations
- `os.scandir()` for fast directory traversal
- Thread pools sized to avoid resource exhaustion
- Priority queues to find value quickly
- Early termination respects time limits

### Detection Avoidance
- Looks like legitimate file indexing/backup software
- No unusual API calls or privilege escalation
- Configurable thread limits to avoid CPU spikes
- Optional stealth profile for long-term persistence

## Output Format

**JSONL Streaming** (one JSON object per line):
```json
{"type": "scan_metadata", "scan_id": "scan_1234567890", ...}
{"type": "finding", "file_path": "C:\\Users\\...", "severity": "HIGH", ...}
{"type": "finding", "file_path": "C:\\Users\\...", "severity": "CRITICAL", ...}
{"type": "errors", "errors": ["Access denied: C:\\..."]}
```

**Benefits:**
- Survives crashes (partial results preserved)
- Streamable for real-time monitoring
- Easy to parse and filter
- Compact for network exfiltration

## Implementation Status

✅ **Core Engine** - Multi-threaded scanner with three-phase execution  
✅ **Value Taxonomy** - 6 categories, 400+ detection patterns  
✅ **CLI Interface** - 4 scan profiles with full configuration  
✅ **Data Models** - Rich findings with metadata and scoring  
✅ **Error Handling** - Graceful degradation for OPSEC  
✅ **Testing** - Basic functionality verification  

### File Structure
```
treasure_hunter/
├── __init__.py           # Package exports and version
├── models.py            # Data structures and scoring
├── scanner.py           # Main scanning engine
├── cli.py              # Command-line interface
└── rules/
    ├── __init__.py      # Rules package exports
    └── value_taxonomy.py # Value categories and patterns
```

## Testing

Basic functionality test included:
```bash
python3 test_basic.py
```

Creates sample valuable files and verifies detection accuracy.

## Next Steps

**For Production Use:**
1. **Windows Testing** - Verify path patterns on actual Windows targets
2. **Content Analysis** - Add more specific regex patterns for credentials
3. **Performance Tuning** - Benchmark against large file systems
4. **Evasion Testing** - Validate against AV/EDR solutions
5. **USB Deployment** - Package with Nuitka for portable execution

**Enhanced Features:**
1. **DPAPI Integration** - Decrypt Windows credential stores
2. **Database Modules** - Parse SQLite, registry, browser databases  
3. **Network Drives** - SMB/UNC path enumeration
4. **Compression** - Handle password-protected archives
5. **Memory Strings** - Scan process memory for secrets

## Operational Usage

**Quick Assessment** (5 minutes):
```bash
python3 -m treasure_hunter -p smash -t "C:\Users" -o quick.jsonl
```

**Full Intelligence Gathering** (2+ hours):
```bash
python3 -m treasure_hunter -p full -t "C:\Users" "D:\" "\\server\share" -o full.jsonl
```

**Long-term Persistence** (background):
```bash
nohup python3 -m treasure_hunter -p stealth -o stealth.jsonl 2>/dev/null &
```

The implementation provides a solid foundation for red team file discovery operations with excellent OPSEC characteristics and operational flexibility.