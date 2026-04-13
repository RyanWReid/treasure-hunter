"""Tests for credential quality assessment.

Uses realistic credential sets that mirror what you'd find on a real
corporate workstation: reused passwords across services, weak admin
passwords, common defaults, and mixed-strength credential pools.
"""

from __future__ import annotations

import pytest

from treasure_hunter.credential_audit import (
    CredentialAuditResult,
    assess_password_strength,
    audit_credentials,
)
from treasure_hunter.grabbers.models import ExtractedCredential


def _cred(username="user", password="", url="", source="browser", app="Chrome"):
    return ExtractedCredential(
        source_module=source,
        credential_type="password",
        target_application=app,
        url=url,
        username=username,
        decrypted_value=password,
    )


# ===========================================================================
# Password strength assessment
# ===========================================================================

class TestPasswordStrength:
    def test_empty_password(self):
        s = assess_password_strength("")
        assert s.rating == "empty"
        assert s.score == 0

    def test_common_password(self):
        s = assess_password_strength("password")
        assert s.rating == "weak"
        assert "Common/default password" in s.issues

    def test_common_password_case_insensitive(self):
        s = assess_password_strength("Password")
        assert "Common/default password" in s.issues

    def test_numeric_only(self):
        s = assess_password_strength("123456")
        assert s.rating == "weak"
        assert "All digits" in s.issues

    def test_short_password(self):
        s = assess_password_strength("ab1")
        assert s.rating == "weak"

    def test_fair_password(self):
        s = assess_password_strength("Winter2024")
        assert s.rating in ("fair", "good")

    def test_good_password(self):
        s = assess_password_strength("C0rp@Summer2024")
        assert s.rating in ("good", "strong")
        assert s.score >= 50

    def test_strong_password(self):
        s = assess_password_strength("x#K9$mPq!vR2&wL5nZ@8")
        assert s.rating == "strong"
        assert s.score >= 70

    def test_repeated_chars_penalty(self):
        s = assess_password_strength("aaaaaa1234")
        assert "Repeated characters" in s.issues

    def test_all_lowercase_penalty(self):
        s = assess_password_strength("longpasswordhere")
        assert "All lowercase letters" in s.issues

    def test_score_range(self):
        for pw in ["", "a", "password", "x#K9$mPq!vR2"]:
            s = assess_password_strength(pw)
            assert 0 <= s.score <= 100


# ===========================================================================
# Full credential audit
# ===========================================================================

class TestCredentialAudit:
    def test_empty_credentials(self):
        result = audit_credentials([])
        assert result.total_credentials == 0
        assert result.total_passwords == 0

    def test_skips_non_password_types(self):
        creds = [
            ExtractedCredential(
                source_module="browser", credential_type="cookie",
                target_application="Chrome", username="SID",
                decrypted_value="session_value",
            ),
            ExtractedCredential(
                source_module="messaging", credential_type="token",
                target_application="Slack", username="bot",
                decrypted_value="xoxb-123",
            ),
        ]
        result = audit_credentials(creds)
        assert result.total_passwords == 0

    def test_detects_password_reuse(self):
        """Same password used for Gmail and corporate VPN."""
        creds = [
            _cred("john.doe", "Summer2024!", "https://mail.google.com"),
            _cred("jdoe", "Summer2024!", "https://vpn.corp.local"),
            _cred("admin", "DifferentPw789!", "https://portal.internal"),
        ]
        result = audit_credentials(creds)
        assert result.total_passwords == 3
        assert result.unique_passwords == 2
        assert len(result.reused_passwords) == 1
        assert result.reused_passwords[0]["reuse_count"] == 2

    def test_detects_common_passwords(self):
        creds = [
            _cred("admin", "password123", "https://router.local"),
            _cred("user", "qwerty", "https://app.internal"),
            _cred("dev", "xK#9mP2$vR!", "https://git.corp.local"),
        ]
        result = audit_credentials(creds)
        assert len(result.common_passwords) == 2  # password123 and qwerty

    def test_detects_weak_passwords(self):
        creds = [
            _cred("admin", "123456"),
            _cred("root", "toor"),
            _cred("user", "C0mpl3x!P@ssw0rd#2024"),
        ]
        result = audit_credentials(creds)
        assert len(result.weak_passwords) >= 2
        assert result.strength_distribution.get("weak", 0) >= 2

    def test_detects_high_value_accounts(self):
        """Accounts matching admin/service patterns."""
        creds = [
            _cred("administrator", "AdminPw123!"),
            _cred("svc_sqlbackup", "B@ckup2024"),
            _cred("john.doe", "UserPw456!"),
            _cred("deploy_bot", "D3pl0y!"),
            _cred("domain.admin", "DA_Pw789!"),
        ]
        result = audit_credentials(creds)
        hv_usernames = {a["username"] for a in result.high_value_accounts}
        assert "administrator" in hv_usernames
        assert "svc_sqlbackup" in hv_usernames
        assert "deploy_bot" in hv_usernames
        assert "domain.admin" in hv_usernames
        assert "john.doe" not in hv_usernames

    def test_strength_distribution(self):
        creds = [
            _cred("u1", "password"),       # weak (common)
            _cred("u2", "123456"),          # weak
            _cred("u3", "Winter2024"),      # fair/good
            _cred("u4", "x#K9$mPq!vR2"),   # strong
        ]
        result = audit_credentials(creds)
        assert "weak" in result.strength_distribution
        assert sum(result.strength_distribution.values()) == 4

    def test_realistic_corporate_workstation(self):
        """Simulates what you'd actually find on a compromised workstation."""
        creds = [
            # Chrome saved passwords
            _cred("john.doe@corp.com", "Corp@2024!", "https://mail.corp.com", "browser", "Chrome"),
            _cred("john.doe@corp.com", "Corp@2024!", "https://sharepoint.corp.com", "browser", "Chrome"),
            _cred("johndoe", "Corp@2024!", "https://vpn.corp.com", "browser", "Chrome"),
            _cred("john.doe", "MyPersonal123", "https://facebook.com", "browser", "Chrome"),
            _cred("jdoe_admin", "Admin#Temp1", "https://admin.corp.com", "browser", "Chrome"),
            # FileZilla
            _cred("deploy", "password", "ftp://files.corp.com", "remote_access", "FileZilla"),
            # AWS
            _cred("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "", "cloud_cred", "AWS"),
            # Git
            _cred("john.doe", "ghp_ABCdef1234567890abcdef1234567890AB", "https://github.com", "git_cred", "Git"),
        ]
        result = audit_credentials(creds)

        # Should detect Corp@2024! used 3 times
        assert len(result.reused_passwords) >= 1
        max_reuse = max(r["reuse_count"] for r in result.reused_passwords)
        assert max_reuse >= 3

        # Should flag "password" as common
        assert len(result.common_passwords) >= 1

        # Should flag jdoe_admin as high-value
        hv = {a["username"] for a in result.high_value_accounts}
        assert "jdoe_admin" in hv

        # Should have a mix of strengths
        assert result.total_passwords == 8
        assert result.unique_passwords < 8  # Due to reuse

    def test_to_dict(self):
        result = CredentialAuditResult(
            total_credentials=10,
            total_passwords=5,
            unique_passwords=3,
        )
        d = result.to_dict()
        assert d["total_credentials"] == 10
        assert d["total_passwords"] == 5
        assert isinstance(d["reused_passwords"], list)
