"""Tests for CloudCredGrabber with fixture files."""

import json
import tempfile
from pathlib import Path

from treasure_hunter.grabbers.cloud_cred import CloudCredGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str) -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    return gctx


class TestAWSCredentials:
    def test_parses_access_keys(self):
        with tempfile.TemporaryDirectory() as home:
            aws_dir = Path(home) / ".aws"
            aws_dir.mkdir()
            (aws_dir / "credentials").write_text(
                "[default]\n"
                "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "\n"
                "[production]\n"
                "aws_access_key_id = AKIAI44QH8DHBEXAMPLE\n"
                "aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY\n"
                "aws_session_token = FwoGZXIvYXdzEBY...\n"
            )

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) == 2
            assert result.credentials[0].username.startswith("[default]")
            assert "AKIAIOSFODNN7EXAMPLE" in result.credentials[0].username
            assert result.credentials[0].decrypted_value == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            assert result.credentials[1].notes == "session_token=yes"


class TestAzureTokens:
    def test_parses_access_tokens_json(self):
        with tempfile.TemporaryDirectory() as home:
            azure_dir = Path(home) / ".azure"
            azure_dir.mkdir()
            (azure_dir / "accessTokens.json").write_text(json.dumps([
                {
                    "tokenType": "Bearer",
                    "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1",
                    "refreshToken": "0.ARoAv4j5cvGGr0GRqy180BHbR2LONGREFRESHTOKEN",
                    "resource": "https://management.azure.com/",
                }
            ]))

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) >= 1
            token_creds = [c for c in result.credentials if c.target_application == "Azure"]
            assert len(token_creds) >= 1


class TestDockerConfig:
    def test_parses_registry_auth(self):
        with tempfile.TemporaryDirectory() as home:
            docker_dir = Path(home) / ".docker"
            docker_dir.mkdir()

            import base64
            auth = base64.b64encode(b"admin:supersecret").decode()
            (docker_dir / "config.json").write_text(json.dumps({
                "auths": {
                    "https://registry.example.com": {"auth": auth},
                    "ghcr.io": {"auth": base64.b64encode(b"user:ghp_token123").decode()},
                }
            }))

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert result.status == GrabberStatus.COMPLETED
            docker_creds = [c for c in result.credentials if c.target_application == "Docker"]
            assert len(docker_creds) == 2
            assert docker_creds[0].username == "admin"
            assert docker_creds[0].decrypted_value == "supersecret"
            assert docker_creds[0].url == "https://registry.example.com"


class TestKubeConfig:
    def test_parses_tokens_and_endpoints(self):
        with tempfile.TemporaryDirectory() as home:
            kube_dir = Path(home) / ".kube"
            kube_dir.mkdir()
            (kube_dir / "config").write_text(
                "apiVersion: v1\n"
                "clusters:\n"
                "- cluster:\n"
                "    server: https://10.0.0.1:6443\n"
                "users:\n"
                "- name: admin\n"
                "  user:\n"
                "    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ.test.signature\n"
            )

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            k8s_creds = [c for c in result.credentials if c.target_application == "Kubernetes"]
            assert len(k8s_creds) >= 1
            tokens = [c for c in k8s_creds if c.credential_type == "token" and c.decrypted_value]
            assert len(tokens) >= 1


class TestVaultToken:
    def test_parses_token_file(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".vault-token").write_text("hvs.CAESIJlVxF8N0Vu9BhKjQlRpz9XYZEXAMPLETOKENVALUE\n")

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            vault_creds = [c for c in result.credentials if c.target_application == "Vault"]
            assert len(vault_creds) == 1
            assert vault_creds[0].decrypted_value.startswith("hvs.")


class TestGHCli:
    def test_parses_hosts_yml(self):
        with tempfile.TemporaryDirectory() as home:
            gh_dir = Path(home) / ".config" / "gh"
            gh_dir.mkdir(parents=True)
            (gh_dir / "hosts.yml").write_text(
                "github.com:\n"
                "    oauth_token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12\n"
                "    user: testuser\n"
                "    git_protocol: ssh\n"
            )

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            gh_creds = [c for c in result.credentials if c.target_application == "GitHub CLI"]
            assert len(gh_creds) == 1
            assert gh_creds[0].decrypted_value.startswith("ghp_")


class TestNetrc:
    def test_parses_machine_entries(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".netrc").write_text(
                "machine github.com login user1 password ghp_token123456789\n"
                "machine api.heroku.com login user2 password heroku-secret-key\n"
            )

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            netrc_creds = [c for c in result.credentials if c.target_application == "netrc"]
            assert len(netrc_creds) == 2
            assert netrc_creds[0].url == "github.com"
            assert netrc_creds[0].username == "user1"


class TestPreflightCheck:
    def test_returns_false_when_no_files(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is False

    def test_returns_true_when_aws_exists(self):
        with tempfile.TemporaryDirectory() as home:
            aws_dir = Path(home) / ".aws"
            aws_dir.mkdir()
            (aws_dir / "credentials").write_text("[default]\naws_access_key_id=test\n")

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is True


class TestFindingsGenerated:
    def test_creates_findings_for_extracted_creds(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".vault-token").write_text("hvs.EXAMPLETOKENVALUE1234567890")

            grabber = CloudCredGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.findings) >= 1
            assert result.findings[0].total_score >= 75
            assert "[cloud_cred]" in result.findings[0].signals[0].description
