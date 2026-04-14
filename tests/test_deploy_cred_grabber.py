"""Tests for deployment credential extraction with realistic fixtures."""

import base64
import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.deploy_cred import (
    DeployCredGrabber,
    _extract_unattend_passwords,
    _extract_webconfig_creds,
    _extract_apphost_creds,
)
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# Realistic Unattend.xml with Base64-encoded password
# "P@ssw0rd123" in UTF-16LE + Base64 = UABAAHMAcwB3ADAAcgBkADEAMgAzAA==
_UNATTEND_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>Administrator</Username>
        <Domain>CORP</Domain>
        <Password>
          <Value>UABAAHMAcwB3ADAAcgBkADEAMgAzAA==</Value>
          <PlainText>false</PlainText>
        </Password>
      </AutoLogon>
      <UserAccounts>
        <AdministratorPassword>
          <Value>UABAAHMAcwB3ADAAcgBkADEAMgAzAA==</Value>
          <PlainText>false</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"""

# Realistic web.config with connection string
_WEB_CONFIG = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="ProdDB" connectionString="Server=db01.corp.local;Database=AppDB;User Id=sa;Password=Pr0dP@ss!2024" />
    <add name="ReadOnly" connectionString="Server=db02.corp.local;Database=AppDB;User Id=readonly;Password=R3ad0nly!" />
  </connectionStrings>
  <appSettings>
    <add key="API_SECRET_KEY" value="sk-prod-ABCdef123456789012345678" />
    <add key="LogLevel" value="Info" />
  </appSettings>
</configuration>
"""

# IIS applicationHost.config with app pool credentials
_APPHOST_CONFIG = """\
<configuration>
  <system.applicationHost>
    <applicationPools>
      <add name="CorpAppPool" managedRuntimeVersion="v4.0">
        <processModel userName="CORP\\svc_webapp" password="W3bApp!2024" identityType="SpecificUser" />
      </add>
    </applicationPools>
  </system.applicationHost>
</configuration>
"""

# Clean web.config (no creds)
_WEB_CONFIG_CLEAN = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.web>
    <compilation debug="false" targetFramework="4.8" />
  </system.web>
</configuration>
"""


class TestUnattendParsing:
    def test_extracts_base64_password(self):
        entries = _extract_unattend_passwords("unattend.xml", _UNATTEND_XML)
        assert len(entries) >= 1
        # At least one should have a decoded password
        decoded = [e for e in entries if e["password_decoded"]]
        assert len(decoded) >= 1

    def test_extracts_autologon_username(self):
        entries = _extract_unattend_passwords("unattend.xml", _UNATTEND_XML)
        usernames = [e["username"] for e in entries if e["username"]]
        # Should find Administrator (from AutoLogon)
        assert any("Administrator" in u for u in usernames)

    def test_handles_malformed_xml(self):
        entries = _extract_unattend_passwords("bad.xml", "<not valid>xml<")
        assert entries == []

    def test_handles_empty_content(self):
        entries = _extract_unattend_passwords("empty.xml", "")
        assert entries == []

    def test_no_password_elements(self):
        entries = _extract_unattend_passwords("clean.xml", '<?xml version="1.0"?><unattend/>')
        assert entries == []


class TestWebConfigParsing:
    def test_extracts_connection_string_passwords(self):
        entries = _extract_webconfig_creds("web.config", _WEB_CONFIG)
        pw_entries = [e for e in entries if e["password_decoded"]]
        assert len(pw_entries) >= 2  # ProdDB + ReadOnly

    def test_extracts_appsetting_secrets(self):
        entries = _extract_webconfig_creds("web.config", _WEB_CONFIG)
        secret_entries = [e for e in entries if "API_SECRET_KEY" in e.get("username", "")]
        assert len(secret_entries) >= 1

    def test_skips_non_secret_settings(self):
        entries = _extract_webconfig_creds("web.config", _WEB_CONFIG)
        # LogLevel=Info should NOT be extracted
        log_entries = [e for e in entries if "LogLevel" in e.get("username", "")]
        assert len(log_entries) == 0

    def test_clean_config_no_creds(self):
        entries = _extract_webconfig_creds("web.config", _WEB_CONFIG_CLEAN)
        assert len(entries) == 0


class TestAppHostParsing:
    def test_extracts_app_pool_credentials(self):
        entries = _extract_apphost_creds("applicationHost.config", _APPHOST_CONFIG)
        assert len(entries) >= 1
        assert entries[0]["username"] == "CORP\\svc_webapp"
        assert entries[0]["password_decoded"] == "W3bApp!2024"


class TestDeployCredGrabberExecute:
    def test_finds_unattend_in_target_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            panther = Path(tmpdir) / "Windows" / "Panther"
            panther.mkdir(parents=True)
            (panther / "Unattend.xml").write_text(_UNATTEND_XML)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            g = DeployCredGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) >= 1
            assert result.credentials[0].target_application == "Windows Deployment"

    def test_finds_webconfig_in_target_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "web.config").write_text(_WEB_CONFIG)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            g = DeployCredGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            creds = [c for c in result.credentials if c.target_application == "IIS Configuration"]
            assert len(creds) >= 2

    def test_handles_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            g = DeployCredGrabber()
            result = g.execute(gctx)
            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) == 0

    def test_handles_permission_error(self):
        ctx = ScanContext(target_paths=["/nonexistent"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, user_profile_path="/nonexistent")
        g = DeployCredGrabber()
        result = g.execute(gctx)
        assert result.status == GrabberStatus.COMPLETED
