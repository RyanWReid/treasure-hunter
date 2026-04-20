"""Tests for credential export in various formats."""

import csv
import json
import tempfile
from io import StringIO
from pathlib import Path

import pytest

from treasure_hunter.credential_export import export_credentials
from treasure_hunter.grabbers.models import ExtractedCredential


def _cred(username="admin", password="pass123", url="https://app.com",
          source="browser", app="Chrome", ctype="password"):
    return ExtractedCredential(
        source_module=source, credential_type=ctype,
        target_application=app, url=url,
        username=username, decrypted_value=password,
    )


class TestCSVExport:
    def test_csv_has_headers(self):
        creds = [_cred()]
        output = export_credentials(creds, "csv")
        reader = csv.reader(StringIO(output))
        headers = next(reader)
        assert "username" in headers
        assert "password" in headers
        assert "url" in headers

    def test_csv_exact_values(self):
        creds = [_cred(username="john", password="SecretPw!", url="https://mail.corp.local")]
        output = export_credentials(creds, "csv")
        assert "john" in output
        assert "SecretPw!" in output
        assert "mail.corp.local" in output

    def test_csv_writes_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "creds.csv")
            creds = [_cred()]
            export_credentials(creds, "csv", path)
            assert Path(path).exists()
            assert Path(path).stat().st_size > 50


class TestNetExecExport:
    def test_format_user_pass(self):
        creds = [_cred(username="admin", password="Pass123!")]
        output = export_credentials(creds, "netexec")
        assert "admin:Pass123!" in output

    def test_domain_user_format(self):
        creds = [_cred(username="CORP\\admin", password="DomPass!")]
        output = export_credentials(creds, "netexec")
        assert "CORP/admin:DomPass!" in output

    def test_skips_non_password_types(self):
        creds = [
            _cred(ctype="token", username="bot", password="tok123"),
            _cred(ctype="password", username="admin", password="real"),
        ]
        output = export_credentials(creds, "netexec")
        assert "admin:real" in output
        assert "bot" not in output

    def test_skips_empty_passwords(self):
        creds = [_cred(username="admin", password="")]
        output = export_credentials(creds, "netexec")
        assert output.strip() == ""

    def test_deduplicates(self):
        creds = [_cred(), _cred()]  # same cred twice
        output = export_credentials(creds, "netexec")
        lines = [l for l in output.strip().split("\n") if l]
        assert len(lines) == 1


class TestPlaintextExport:
    def test_user_pass_format(self):
        creds = [_cred(username="user1", password="pw1")]
        output = export_credentials(creds, "plaintext")
        assert "user1:pw1" in output

    def test_deduplicates(self):
        creds = [_cred(), _cred(), _cred()]
        output = export_credentials(creds, "plaintext")
        lines = [l for l in output.strip().split("\n") if l]
        assert len(lines) == 1


class TestJSONExport:
    def test_valid_json(self):
        creds = [_cred()]
        output = export_credentials(creds, "json")
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["username"] == "admin"

    def test_all_fields_present(self):
        creds = [_cred()]
        output = export_credentials(creds, "json")
        data = json.loads(output)
        assert "source_module" in data[0]
        assert "credential_type" in data[0]
        assert "target_application" in data[0]


class TestInvalidFormat:
    def test_raises_on_unknown_format(self):
        with pytest.raises(ValueError, match="Unknown format"):
            export_credentials([], "xml")

    def test_aliases_work(self):
        creds = [_cred()]
        # nxc and cme should work as aliases for netexec
        output_nxc = export_credentials(creds, "nxc")
        output_cme = export_credentials(creds, "cme")
        output_netexec = export_credentials(creds, "netexec")
        assert output_nxc == output_netexec
        assert output_cme == output_netexec
