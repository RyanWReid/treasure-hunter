"""
VALUE TAXONOMY — What makes a file "valuable"?

This is the core intelligence of treasure-hunter. Every detection rule maps
back to one of these value categories. The taxonomy is designed for corporate
Windows targets and covers the full spectrum of what a red team operator
would want to find on a compromised workstation or file share.

Each category has:
  - A base score weight (how valuable this category is relative to others)
  - File extension signatures
  - Filename keyword patterns
  - Path patterns (Windows-specific locations)
  - Content patterns (regex for file contents)

The scoring is ADDITIVE — a file hitting multiple categories stacks scores.
A KeePass database named "admin-passwords.kdbx" modified yesterday scores
higher than a generic .pdf because it fires: extension + keyword + recency.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ValueCategory:
    """Defines one category of valuable file with all its detection signals."""

    name: str
    description: str
    base_weight: int  # Multiplier for this category (1-5)
    extensions: list[str] = field(default_factory=list)
    filename_keywords: list[str] = field(default_factory=list)
    path_patterns: list[str] = field(default_factory=list)  # Windows path globs
    content_patterns: list[str] = field(default_factory=list)  # Regex patterns


# ---------------------------------------------------------------------------
# Category 1: CREDENTIALS & SECRETS
# The crown jewels. Passwords, keys, tokens, certificates.
# Base weight: 5 (highest) — immediate exploit potential.
# ---------------------------------------------------------------------------
CREDENTIALS = ValueCategory(
    name="credentials",
    description="Passwords, keys, tokens, certificates — immediate access value",
    base_weight=5,
    extensions=[
        # Password managers
        ".kdbx", ".kdb", ".1pif", ".agilekeychain", ".opvault",
        # SSH / crypto keys
        ".pem", ".key", ".ppk", ".pub", ".rsa", ".dsa", ".ecdsa", ".ed25519",
        # Certificates & keystores
        ".pfx", ".p12", ".jks", ".keystore", ".crt", ".cer", ".der",
        # Environment / config secrets
        ".env", ".env.local", ".env.production", ".env.staging",
        # GPG
        ".gpg", ".asc", ".pgp",
        # Misc credential stores
        ".htpasswd", ".netrc", ".npmrc", ".pypirc",
        # Database password files
        ".pgpass", ".mylogin.cnf",
    ],
    filename_keywords=[
        "password", "passwd", "passwords", "credential", "credentials",
        "secret", "secrets", "token", "tokens", "api_key", "apikey",
        "api-key", "auth", "login", "master", "private", "id_rsa",
        "id_dsa", "id_ecdsa", "id_ed25519", "keyfile", "keytab",
        "service_account", "service-account", "access_key", "secret_key",
        "wallet", "seed", "mnemonic", "recovery", "2fa", "otp",
        "totp", "backup_codes", "backup-codes",
        # Browser credential databases
        "login data", "local state", "web data",
        # Remote access tool credential files
        "recentservers", "sitemanager",  # FileZilla (cleartext passwords!)
        "confcons",  # mRemoteNG (encrypted passwords)
        "winscp",  # WinSCP session passwords
        "mobaxterm",  # MobaXterm
        # Cloud CLI token files
        "accesstokens", "azureprofile",
        # System artifacts with credentials
        "consolehost_history",  # PowerShell history (typed passwords)
        "plum",  # Windows Sticky Notes (users paste creds)
        # Git credential stores
        "git-credentials",
        # Vault token
        "vault-token",
    ],
    path_patterns=[
        # ---------------------------------------------------------------
        # Windows credential stores
        # ---------------------------------------------------------------
        r"*\AppData\Roaming\Microsoft\Credentials\*",
        r"*\AppData\Local\Microsoft\Credentials\*",
        r"*\AppData\Roaming\Microsoft\Protect\*",
        r"*\AppData\Local\Microsoft\Vault\*",
        # ---------------------------------------------------------------
        # Browser credential databases (Chrome, Edge, Brave, Opera)
        # ---------------------------------------------------------------
        # Chromium — Login Data (saved passwords)
        r"*\AppData\Local\Google\Chrome\User Data\*\Login Data",
        r"*\AppData\Local\Microsoft\Edge\User Data\*\Login Data",
        r"*\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Login Data",
        # Chromium — Cookies (session tokens = instant account access)
        r"*\AppData\Local\Google\Chrome\User Data\*\Network\Cookies",
        r"*\AppData\Local\Microsoft\Edge\User Data\*\Network\Cookies",
        r"*\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Network\Cookies",
        # Chromium — Local State (AES state key for Chrome 80+ decryption)
        r"*\AppData\Local\Google\Chrome\User Data\Local State",
        r"*\AppData\Local\Microsoft\Edge\User Data\Local State",
        # Chromium — Web Data (autofill, saved credit cards, addresses)
        r"*\AppData\Local\Google\Chrome\User Data\*\Web Data",
        r"*\AppData\Local\Microsoft\Edge\User Data\*\Web Data",
        # Firefox — credentials & encryption keys
        r"*\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json",
        r"*\AppData\Roaming\Mozilla\Firefox\Profiles\*\key4.db",
        r"*\AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite",
        # ---------------------------------------------------------------
        # Messaging app tokens (LevelDB = instant account access)
        # ---------------------------------------------------------------
        r"*\AppData\Roaming\Slack\Local Storage\leveldb\*",
        r"*\AppData\Roaming\discord\Local Storage\leveldb\*",
        r"*\AppData\Roaming\Microsoft\Teams\Local Storage\leveldb\*",
        r"*\AppData\Roaming\Signal\*",
        r"*\AppData\Roaming\Telegram Desktop\tdata\*",
        # ---------------------------------------------------------------
        # Remote access tool credential stores
        # ---------------------------------------------------------------
        # FileZilla (stores passwords in CLEARTEXT XML!)
        r"*\AppData\Roaming\FileZilla\recentservers.xml",
        r"*\AppData\Roaming\FileZilla\sitemanager.xml",
        # WinSCP (session passwords in INI or registry)
        r"*\AppData\Roaming\WinSCP.ini",
        # mRemoteNG (encrypted but crackable connection configs)
        r"*\AppData\Roaming\mRemoteNG\confCons.xml",
        # MobaXterm
        r"*\AppData\Roaming\MobaXterm\MobaXterm.ini",
        # SecureCRT sessions
        r"*\AppData\Roaming\VanDyke\Config\Sessions\*",
        # ---------------------------------------------------------------
        # SSH keys
        # ---------------------------------------------------------------
        r"*\.ssh\*",
        # ---------------------------------------------------------------
        # Cloud CLI credentials & tokens
        # ---------------------------------------------------------------
        r"*\.aws\credentials",
        r"*\.aws\config",
        r"*\.azure\accessTokens.json",
        r"*\.azure\azureProfile.json",
        r"*\.azure\msal_token_cache.json",
        r"*\.config\gcloud\*",
        r"*\.config\gh\hosts.yml",
        r"*\.terraform.d\credentials.tfrc.json",
        r"*\.vault-token",
        r"*\.config\heroku\credentials",
        r"*\.config\doctl\config.yaml",
        r"*\.config\configstore\firebase-tools.json",
        # Docker
        r"*\.docker\config.json",
        # Kubernetes
        r"*\.kube\config",
        # ---------------------------------------------------------------
        # Git credential stores
        # ---------------------------------------------------------------
        r"*\.git-credentials",
        r"*\.gcm\dpapi_store\*",
        # ---------------------------------------------------------------
        # Database password files
        # ---------------------------------------------------------------
        r"*\.pgpass",
        r"*\.my.cnf",
        r"*\.mylogin.cnf",
        # ---------------------------------------------------------------
        # Package manager credentials
        # ---------------------------------------------------------------
        r"*\.npmrc",
        r"*\.pypirc",
        r"*\.nuget\NuGet.Config",
        r"*\.cargo\credentials.toml",
        r"*\.m2\settings.xml",
        r"*\.gradle\gradle.properties",
        r"*\.composer\auth.json",
        # ---------------------------------------------------------------
        # KeePass databases
        # ---------------------------------------------------------------
        r"*\Documents\*.kdbx",
        # ---------------------------------------------------------------
        # System artifacts containing credentials
        # ---------------------------------------------------------------
        # PowerShell history (users type passwords in commands!)
        r"*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt",
        # Windows Sticky Notes (users paste secrets here constantly)
        r"*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite",
        # WiFi profiles (SSID + cleartext passwords)
        r"*\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*",
    ],
    content_patterns=[
        # AWS keys
        r"AKIA[0-9A-Z]{16}",
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S+",
        # Private keys
        r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----",
        # Generic API keys / tokens
        r"(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token)\s*[=:]\s*['\"]?\w{20,}",
        # Connection strings with passwords
        r"(?:password|passwd|pwd)\s*[=:]\s*[^\s;,]{4,}",
        r"(?:Server|Data Source).*?(?:Password|Pwd)\s*=\s*[^;]+",
        # GitHub / GitLab tokens
        r"gh[ps]_[A-Za-z0-9_]{36,}",
        r"glpat-[A-Za-z0-9\-_]{20,}",
        # Slack tokens
        r"xox[bprs]-[0-9]{10,}-[0-9a-zA-Z]+",
        # Discord tokens
        r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}",
        # Heroku API key
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        # Generic high-entropy secrets in assignments
        r'(?:secret|token|key|password)\s*[=:]\s*["\'][A-Za-z0-9+/=]{32,}["\']',
        # .pgpass format (host:port:db:user:password)
        r"^[^#][^:]+:\d+:[^:]+:[^:]+:[^:]+$",
        # Bearer tokens
        r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        # HashiCorp Vault tokens
        r"hvs\.[A-Za-z0-9]{24,}",
        # Terraform Cloud tokens
        r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,}",
    ],
)

# ---------------------------------------------------------------------------
# Category 2: INFRASTRUCTURE INTEL
# Network configs, remote access, AD data — lateral movement enablers.
# Base weight: 4 — enables pivoting and deeper access.
# ---------------------------------------------------------------------------
INFRASTRUCTURE = ValueCategory(
    name="infrastructure",
    description="Network configs, remote access, AD exports — lateral movement fuel",
    base_weight=4,
    extensions=[
        # Remote access
        ".rdp", ".ovpn", ".vpn", ".pcf",
        # Network configs
        ".conf", ".cfg",
        # Infrastructure-as-code
        ".tf", ".tfstate", ".tfvars",
        # Ansible / automation
        ".yml", ".yaml",  # scored lower unless keywords match too
        # Database connection files
        ".udl", ".dsn",
        # Windows network
        ".admx", ".adml",
        # Oracle network config
        ".ora",
    ],
    filename_keywords=[
        "vpn", "openvpn", "wireguard", "rdp", "ssh", "remote",
        "firewall", "router", "switch", "network", "topology",
        "subnet", "vlan", "dns", "dhcp", "proxy",
        "ansible", "terraform", "puppet", "chef",
        "inventory", "hosts", "hostfile",
        "domain", "ldap", "active_directory", "ad_export",
        "bloodhound", "sharphound", "gpo", "group_policy",
        "backup_config", "running-config", "startup-config",
        "ip_addresses", "ip-addresses", "network_diagram",
        # WiFi profiles (network topology intel)
        "wlansvc", "wifi", "wlan",
        # Oracle / database networking
        "tnsnames", "sqlnet", "odbc",
        # FreeTDS (MS SQL from Linux)
        "freetds",
    ],
    path_patterns=[
        # VPN configs
        r"*\OpenVPN\config\*",
        r"*\WireGuard\*",
        # RDP files
        r"*\Documents\*.rdp",
        r"*\Desktop\*.rdp",
        # Windows admin tools
        r"*\AppData\Roaming\Microsoft\MMC\*",
        # Azure / cloud config
        r"*\.kube\config",
        r"*\.kube\*",
        # Terraform state (contains secrets!)
        r"*\*.tfstate",
        r"*\*.tfstate.backup",
        # Browser history & bookmarks (reveals internal URLs/portals)
        r"*\AppData\Local\Google\Chrome\User Data\*\History",
        r"*\AppData\Local\Google\Chrome\User Data\*\Bookmarks",
        r"*\AppData\Local\Microsoft\Edge\User Data\*\History",
        r"*\AppData\Local\Microsoft\Edge\User Data\*\Bookmarks",
        r"*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite",
        # ODBC / database connection configs
        r"*\odbc.ini",
        r"*\.odbc.ini",
        r"*\freetds.conf",
        # Oracle connection files
        r"*\tnsnames.ora",
        r"*\sqlnet.ora",
        # Recently used files (reveals accessed resources)
        r"*\AppData\Roaming\Microsoft\Windows\Recent\*",
    ],
    content_patterns=[
        # IP addresses in private ranges
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        # LDAP connection strings
        r"(?:ldap|ldaps)://[\w\.\-]+(?::\d+)?",
        # SMB / UNC paths
        r"\\\\[\w\.\-]+\\[\w$]+",
        # SQL Server connection strings
        r"(?:Server|Data Source)\s*=\s*[\w\.\-]+(?:,\d+)?",
        # AD distinguished names
        r"(?:DC|OU|CN)=[\w\s]+,(?:DC|OU|CN)=",
        # JDBC connection strings
        r"jdbc:[a-z]+://[\w\.\-]+(?::\d+)?",
        # MongoDB connection strings
        r"mongodb(?:\+srv)?://[\w\.\-:@]+",
        # Redis connection strings
        r"redis://[\w\.\-:@]+",
    ],
)

# ---------------------------------------------------------------------------
# Category 3: SENSITIVE DOCUMENTS
# PII, financials, legal, internal comms — exfiltration goldmines.
# Base weight: 3 — high value but requires manual triage.
# ---------------------------------------------------------------------------
SENSITIVE_DOCUMENTS = ValueCategory(
    name="sensitive_documents",
    description="PII, financials, legal docs, internal reports — high exfil value",
    base_weight=3,
    extensions=[
        # Office documents
        ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
        ".odt", ".ods", ".odp",
        # PDF
        ".pdf",
        # Outlook / email
        ".pst", ".ost", ".msg", ".eml",
        # Notes
        ".one", ".onetoc2",
        # Misc
        ".rtf", ".csv",
        # Chat / messaging exports
        ".mbox",
    ],
    filename_keywords=[
        # Financial
        "financial", "finance", "budget", "revenue", "salary",
        "payroll", "invoice", "tax", "bank", "account", "statement",
        "profit", "loss", "forecast", "quarterly", "annual_report",
        # PII
        "ssn", "social_security", "driver_license", "passport",
        "employee", "personnel", "hr_", "human_resources",
        "personal", "contact_list", "directory",
        # Legal
        "legal", "contract", "agreement", "nda", "non-disclosure",
        "lawsuit", "litigation", "compliance", "regulatory",
        "patent", "trademark", "intellectual_property",
        # Internal / strategic
        "confidential", "internal", "restricted", "classified",
        "strategic", "roadmap", "merger", "acquisition",
        "board_meeting", "board_minutes", "executive",
        "due_diligence", "audit", "investigation",
        # Messaging exports
        "chat_export", "slack_export", "teams_export",
        "conversation", "messages",
    ],
    path_patterns=[
        r"*\Documents\*",
        r"*\Desktop\*",
        r"*\Downloads\*",
        # Outlook data files
        r"*\AppData\Local\Microsoft\Outlook\*.pst",
        r"*\AppData\Local\Microsoft\Outlook\*.ost",
        # OneDrive / SharePoint sync
        r"*\OneDrive*\*",
        r"*\SharePoint\*",
        # OneNote notebooks
        r"*\AppData\Local\Microsoft\OneNote\*",
        # Obsidian vaults (notes often contain credentials & internal docs)
        r"*\.obsidian\*",
    ],
    content_patterns=[
        # SSN patterns
        r"\b\d{3}-\d{2}-\d{4}\b",
        # Credit card numbers (basic)
        r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
        # Email addresses in bulk (suggests contact lists)
        r"[\w\.\-]+@[\w\.\-]+\.\w{2,}",
        # Confidentiality markers
        r"(?i)\b(?:confidential|internal\s+only|restricted|privileged|attorney.client)\b",
        # HIPAA / medical
        r"(?i)\b(?:hipaa|patient|medical\s+record|diagnosis|prescription)\b",
        # GDPR / privacy
        r"(?i)\b(?:gdpr|data\s+subject|right\s+to\s+erasure|personal\s+data)\b",
    ],
)

# ---------------------------------------------------------------------------
# Category 4: SOURCE CODE & INTELLECTUAL PROPERTY
# Proprietary code, build artifacts, design docs.
# Base weight: 3 — high value, especially unreleased products.
# ---------------------------------------------------------------------------
SOURCE_CODE = ValueCategory(
    name="source_code",
    description="Proprietary code, repos, build artifacts, design documents",
    base_weight=3,
    extensions=[
        # Source code
        ".cs", ".java", ".py", ".js", ".ts", ".go", ".rs", ".cpp",
        ".c", ".h", ".swift", ".kt", ".rb", ".php",
        # Project files
        ".sln", ".csproj", ".vcxproj", ".pbxproj", ".xcworkspace",
        # Build artifacts / packages
        ".nupkg", ".whl", ".jar", ".war", ".dll", ".so",
        # Design / CAD
        ".fig", ".sketch", ".psd", ".ai", ".dwg", ".step", ".stl",
        # Notebooks
        ".ipynb",
    ],
    filename_keywords=[
        "source", "src", "repo", "repository", "codebase",
        "prototype", "poc", "proof_of_concept",
        "design", "architecture", "schema", "spec", "specification",
        "algorithm", "patent_pending", "proprietary",
        "unreleased", "pre-release", "beta", "alpha", "internal_build",
        "firmware", "embedded",
        # CI/CD (may contain deployment secrets)
        "jenkinsfile", "dockerfile", "docker-compose",
        ".gitlab-ci", ".github",
    ],
    path_patterns=[
        # Common dev locations
        r"*\Source\*", r"*\Repos\*", r"*\Projects\*",
        r"*\Development\*", r"*\workspace\*",
        r"*\git\*",
        # Visual Studio
        r"*\Visual Studio*\Projects\*",
        # Build output
        r"*\bin\Release\*",
        r"*\build\*",
        r"*\dist\*",
        r"*\output\*",
        # Git config files (may contain credentials in remote URLs)
        r"*\.git\config",
    ],
    content_patterns=[
        # Copyright notices (indicates proprietary code)
        r"(?i)(?:copyright|©)\s+\d{4}\s+[\w\s]+(?:inc|corp|ltd|llc|co\.)",
        # License headers (proprietary markers)
        r"(?i)(?:proprietary|trade\s+secret|all\s+rights\s+reserved|do\s+not\s+distribute)",
        # Internal package references
        r"(?:internal|private)\.[\w\.]+",
        # Git remote URLs with embedded credentials
        r"https?://[^@\s]+:[^@\s]+@(?:github|gitlab|bitbucket)",
        # CI/CD secrets in config
        r"(?i)(?:deploy_key|ci_token|registry_password)\s*[=:]\s*\S+",
    ],
)

# ---------------------------------------------------------------------------
# Category 5: UNRELEASED SOFTWARE & BUILDS
# Executables, installers, builds that haven't shipped yet.
# Base weight: 4 — competitive intelligence goldmine.
# ---------------------------------------------------------------------------
UNRELEASED_SOFTWARE = ValueCategory(
    name="unreleased_software",
    description="Pre-release executables, installers, builds not yet public",
    base_weight=4,
    extensions=[
        # Executables
        ".exe", ".msi", ".msix", ".appx", ".appxbundle",
        # Installers
        ".wixobj", ".wixpdb",
        # Packages
        ".nupkg", ".appimage",
        # Mobile builds
        ".apk", ".aab", ".ipa",
        # Disk images
        ".iso", ".img", ".vhd", ".vhdx", ".vmdk",
        # Firmware
        ".bin", ".hex", ".fw", ".rom",
    ],
    filename_keywords=[
        "setup", "installer", "install",
        "release", "unreleased", "pre-release", "prerelease",
        "beta", "alpha", "rc", "candidate",
        "nightly", "dev_build", "dev-build", "internal_build",
        "staging", "preview", "canary",
        "firmware", "update", "patch",
        "v0.", "v1.", "v2.",  # Version prefixes
    ],
    path_patterns=[
        r"*\Builds\*",
        r"*\Releases\*",
        r"*\Staging\*",
        r"*\Internal\*",
        r"*\QA\*",
        r"*\Testing\*",
        r"*\bin\Release\*",
        r"*\artifacts\*",
    ],
    content_patterns=[],  # Binaries — content scanning not useful
)

# ---------------------------------------------------------------------------
# Category 6: BACKUPS & ARCHIVES
# Database dumps, system backups, exported data — often unencrypted.
# Base weight: 4 — frequently contain the richest data.
# ---------------------------------------------------------------------------
BACKUPS = ValueCategory(
    name="backups",
    description="Database dumps, system backups, archives — often contain everything",
    base_weight=4,
    extensions=[
        # Archives
        ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz",
        ".tar.gz", ".tgz", ".tar.bz2",
        # Database dumps
        ".sql", ".bak", ".dump", ".dmp",
        # Database files
        ".sqlite", ".sqlite3", ".db", ".mdb", ".accdb", ".ldf", ".mdf",
        # Backup-specific
        ".bkf", ".vbk", ".vrb", ".bkp",
        # Virtual machine snapshots
        ".vmdk", ".vhd", ".vhdx", ".ova", ".ovf",
        # Disk images
        ".img", ".dd", ".raw",
    ],
    filename_keywords=[
        "backup", "bak", "dump", "export", "snapshot",
        "archive", "old", "copy", "restore",
        "full_backup", "full-backup", "daily", "weekly", "monthly",
        "migration", "migrate", "transfer",
        "database", "db_dump", "db-dump", "db_backup", "db-backup",
    ],
    path_patterns=[
        r"*\Backup*\*",
        r"*\backup*\*",
        r"*\Backups\*",
        r"*\Archives\*",
        r"*\Old\*",
        r"*\Migration\*",
        r"*\Temp\*backup*",
    ],
    content_patterns=[
        # SQL dump markers
        r"(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE|ALTER\s+TABLE)",
        r"-- MySQL dump",
        r"-- PostgreSQL database dump",
    ],
)


# ---------------------------------------------------------------------------
# Master registry — all categories in priority order
# ---------------------------------------------------------------------------
ALL_CATEGORIES: list[ValueCategory] = [
    CREDENTIALS,
    UNRELEASED_SOFTWARE,
    INFRASTRUCTURE,
    BACKUPS,
    SENSITIVE_DOCUMENTS,
    SOURCE_CODE,
]

CATEGORY_MAP: dict[str, ValueCategory] = {cat.name: cat for cat in ALL_CATEGORIES}
