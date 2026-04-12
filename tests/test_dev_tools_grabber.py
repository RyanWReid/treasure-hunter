"""Tests for DevToolGrabber."""

import json
import tempfile
from pathlib import Path

from treasure_hunter.grabbers.dev_tools import DevToolGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str) -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    gctx.appdata_roaming = home
    return gctx


class TestNpmrc:
    def test_parses_auth_token(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".npmrc").write_text(
                "//registry.npmjs.org/:_authToken=npm_ABCDEF1234567890\n"
                "//npm.pkg.github.com/:_authToken=ghp_GitHubToken123\n"
            )

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            npm_creds = [c for c in result.credentials if c.target_application == "npm"]
            assert len(npm_creds) == 2
            assert npm_creds[0].decrypted_value == "npm_ABCDEF1234567890"


class TestPypirc:
    def test_parses_upload_credentials(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".pypirc").write_text(
                "[distutils]\n"
                "index-servers = pypi\n\n"
                "[pypi]\n"
                "repository = https://upload.pypi.org/legacy/\n"
                "username = __token__\n"
                "password = pypi-AgEIcHlwaS5vcmcCJGY4ZTc\n"
            )

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            pypi_creds = [c for c in result.credentials if c.target_application == "PyPI"]
            assert len(pypi_creds) == 1
            assert pypi_creds[0].username == "__token__"
            assert pypi_creds[0].decrypted_value.startswith("pypi-")


class TestMavenSettings:
    def test_parses_server_credentials(self):
        with tempfile.TemporaryDirectory() as home:
            m2_dir = Path(home) / ".m2"
            m2_dir.mkdir()
            (m2_dir / "settings.xml").write_text(
                '<settings>\n'
                '  <servers>\n'
                '    <server>\n'
                '      <id>nexus-releases</id>\n'
                '      <username>deployer</username>\n'
                '      <password>DeployerPass123!</password>\n'
                '    </server>\n'
                '  </servers>\n'
                '</settings>\n'
            )

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            maven_creds = [c for c in result.credentials if c.target_application == "Maven"]
            assert len(maven_creds) == 1
            assert maven_creds[0].username == "deployer"
            assert maven_creds[0].decrypted_value == "DeployerPass123!"


class TestGradleProperties:
    def test_parses_credential_properties(self):
        with tempfile.TemporaryDirectory() as home:
            gradle_dir = Path(home) / ".gradle"
            gradle_dir.mkdir()
            (gradle_dir / "gradle.properties").write_text(
                "# Gradle properties\n"
                "org.gradle.jvmargs=-Xmx2048m\n"
                "nexusPassword=SecretNexus123\n"
                "sonatypeToken=ABCDEF1234567890\n"
            )

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            gradle_creds = [c for c in result.credentials if c.target_application == "Gradle"]
            assert len(gradle_creds) == 2


class TestComposerAuth:
    def test_parses_http_basic_auth(self):
        with tempfile.TemporaryDirectory() as home:
            composer_dir = Path(home) / ".composer"
            composer_dir.mkdir()
            (composer_dir / "auth.json").write_text(json.dumps({
                "http-basic": {
                    "repo.packagist.com": {
                        "username": "token",
                        "password": "packagist_api_key_12345"
                    }
                }
            }))

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            composer_creds = [c for c in result.credentials if c.target_application == "Composer"]
            assert len(composer_creds) == 1
            assert composer_creds[0].decrypted_value == "packagist_api_key_12345"


class TestCargoCredentials:
    def test_parses_token(self):
        with tempfile.TemporaryDirectory() as home:
            cargo_dir = Path(home) / ".cargo"
            cargo_dir.mkdir()
            (cargo_dir / "credentials.toml").write_text(
                '[registry]\n'
                'token = "cio_ABCDEF1234567890_cargo_token"\n'
            )

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            cargo_creds = [c for c in result.credentials if c.target_application == "Cargo"]
            assert len(cargo_creds) == 1
            assert "cio_ABCDEF" in cargo_creds[0].decrypted_value


class TestVSCodeSettings:
    def test_extracts_tokens_from_settings(self):
        with tempfile.TemporaryDirectory() as home:
            vscode_dir = Path(home) / "Code" / "User"
            vscode_dir.mkdir(parents=True)
            (vscode_dir / "settings.json").write_text(json.dumps({
                "editor.fontSize": 14,
                "http.proxyAuthorization": "Bearer eyJhbGciOiJIUzI1NiJ9.longtoken",
                "git.credentials.token": "ghp_SomeGitHubTokenInSettings",
            }))

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            vscode_creds = [c for c in result.credentials if c.target_application == "VS Code"]
            assert len(vscode_creds) >= 1
            values = [c.decrypted_value for c in vscode_creds]
            assert any("ghp_" in v or "Bearer" in v for v in values)


class TestPostmanEnvironments:
    def test_extracts_api_keys(self):
        with tempfile.TemporaryDirectory() as home:
            postman_dir = Path(home) / "Postman" / "environments"
            postman_dir.mkdir(parents=True)
            (postman_dir / "prod.json").write_text(json.dumps({
                "name": "Production",
                "values": [
                    {"key": "api_key", "value": "sk_live_1234567890abcdef"},
                    {"key": "base_url", "value": "https://api.example.com"},
                    {"key": "auth_token", "value": "Bearer eyJhbGciOiJIUzI1NiJ9"},
                ]
            }))

            grabber = DevToolGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            postman_creds = [c for c in result.credentials if c.target_application == "Postman"]
            assert len(postman_creds) == 2  # api_key + auth_token (not base_url)
            keys = {c.username for c in postman_creds}
            assert "api_key" in keys
            assert "auth_token" in keys


class TestPreflightCheck:
    def test_false_when_nothing_exists(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = DevToolGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is False
