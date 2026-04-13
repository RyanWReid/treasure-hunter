"""
CREDENTIAL AUDIT -- Post-scan credential quality assessment

Analyzes extracted credentials for:
- Password reuse across services (same password, different URLs)
- Weak/default/common passwords
- Password strength rating
- High-value targets (admin accounts, service accounts, domain accounts)

Run after grabber phase, results included in JSONL output and HTML report.
"""

from __future__ import annotations

import re
import string
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .grabbers.models import ExtractedCredential


# Common/default passwords (top 50 from breach databases)
_COMMON_PASSWORDS = frozenset({
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1",
    "password123", "jesus", "batman", "welcome", "charlie",
    "donald", "admin", "login", "princess", "qwerty123",
    "solo", "admin123", "root", "toor", "changeme",
    "p@ssw0rd", "p@ssword", "pass123", "test", "guest",
    "default", "temp", "winter", "summer", "spring",
})

# Patterns indicating high-value accounts
_ADMIN_PATTERNS = re.compile(
    r"(?:admin|administrator|root|sysadmin|superuser|sa|dba|"
    r"svc_|service_|backup|deploy|jenkins|ansible|terraform|"
    r"domain.admin|enterprise.admin)",
    re.IGNORECASE,
)


@dataclass
class PasswordStrength:
    """Assessment of a single password's strength."""
    password: str
    score: int = 0  # 0-100
    rating: str = ""  # "weak", "fair", "good", "strong"
    issues: list[str] = field(default_factory=list)


@dataclass
class CredentialAuditResult:
    """Complete credential audit results."""
    total_credentials: int = 0
    total_passwords: int = 0
    unique_passwords: int = 0
    reused_passwords: list[dict] = field(default_factory=list)
    weak_passwords: list[dict] = field(default_factory=list)
    common_passwords: list[dict] = field(default_factory=list)
    high_value_accounts: list[dict] = field(default_factory=list)
    strength_distribution: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_credentials": self.total_credentials,
            "total_passwords": self.total_passwords,
            "unique_passwords": self.unique_passwords,
            "reused_passwords": self.reused_passwords,
            "weak_passwords": self.weak_passwords,
            "common_passwords": self.common_passwords,
            "high_value_accounts": self.high_value_accounts,
            "strength_distribution": self.strength_distribution,
        }


def assess_password_strength(password: str) -> PasswordStrength:
    """Rate a password's strength on a 0-100 scale."""
    result = PasswordStrength(password=password)

    if not password:
        result.rating = "empty"
        result.issues.append("Empty password")
        return result

    score = 0
    length = len(password)

    # Length scoring (0-30 points)
    if length >= 16:
        score += 30
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        result.issues.append(f"Very short ({length} chars)")

    # Character class diversity (0-40 points)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))
    classes = sum([has_lower, has_upper, has_digit, has_special])
    score += classes * 10

    if classes < 2:
        result.issues.append("Single character class")

    # Entropy-like scoring (0-20 points)
    unique_chars = len(set(password))
    if unique_chars >= 10:
        score += 20
    elif unique_chars >= 6:
        score += 12
    elif unique_chars >= 4:
        score += 5
    else:
        result.issues.append("Low character diversity")

    # Pattern penalties
    if re.match(r"^[a-z]+$", password):
        score -= 10
        result.issues.append("All lowercase letters")
    if re.match(r"^\d+$", password):
        score -= 15
        result.issues.append("All digits")
    if re.search(r"(.)\1{2,}", password):
        score -= 5
        result.issues.append("Repeated characters")
    if re.search(r"(?:123|abc|qwe|pass|admin)", password, re.IGNORECASE):
        score -= 10
        result.issues.append("Common pattern")

    # Common password check
    if password.lower() in _COMMON_PASSWORDS:
        score = min(score, 5)
        result.issues.append("Common/default password")

    result.score = max(0, min(100, score))

    if result.score >= 70:
        result.rating = "strong"
    elif result.score >= 50:
        result.rating = "good"
    elif result.score >= 30:
        result.rating = "fair"
    else:
        result.rating = "weak"

    return result


def audit_credentials(credentials: list[ExtractedCredential]) -> CredentialAuditResult:
    """Run a full audit on extracted credentials."""
    result = CredentialAuditResult()
    result.total_credentials = len(credentials)

    # Filter to password-type credentials with decrypted values
    passwords = [
        c for c in credentials
        if c.credential_type == "password" and c.decrypted_value
    ]
    result.total_passwords = len(passwords)

    if not passwords:
        return result

    # Password reuse detection
    pw_to_accounts: dict[str, list[dict]] = {}
    for cred in passwords:
        pw = cred.decrypted_value
        pw_to_accounts.setdefault(pw, []).append({
            "username": cred.username,
            "url": cred.url,
            "source": cred.source_module,
            "application": cred.target_application,
        })

    result.unique_passwords = len(pw_to_accounts)

    for pw, accounts in pw_to_accounts.items():
        if len(accounts) > 1:
            result.reused_passwords.append({
                "password_hint": pw[:2] + "*" * (len(pw) - 2) if len(pw) > 2 else "**",
                "reuse_count": len(accounts),
                "accounts": accounts,
            })

    # Strength assessment
    strength_counts = Counter()
    for cred in passwords:
        strength = assess_password_strength(cred.decrypted_value)
        strength_counts[strength.rating] += 1

        if strength.rating == "weak":
            result.weak_passwords.append({
                "username": cred.username,
                "url": cred.url,
                "source": cred.source_module,
                "score": strength.score,
                "issues": strength.issues,
            })

        if cred.decrypted_value.lower() in _COMMON_PASSWORDS:
            result.common_passwords.append({
                "username": cred.username,
                "url": cred.url,
                "source": cred.source_module,
            })

    result.strength_distribution = dict(strength_counts)

    # High-value account detection
    for cred in passwords:
        username = cred.username
        if _ADMIN_PATTERNS.search(username):
            result.high_value_accounts.append({
                "username": username,
                "url": cred.url,
                "source": cred.source_module,
                "application": cred.target_application,
                "has_password": bool(cred.decrypted_value),
            })

    # Sort reused passwords by count (most reused first)
    result.reused_passwords.sort(key=lambda x: x["reuse_count"], reverse=True)

    return result
