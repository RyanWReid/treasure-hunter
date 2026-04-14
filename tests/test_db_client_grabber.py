"""Tests for database client credential grabber with realistic fixtures."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.db_client import DBClientGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# Realistic DBeaver credentials-config.json
_DBEAVER_CREDS = json.dumps({
    "postgresql-jdbc-prod": {
        "user": "app_admin",
        "password": "YXBwX3Bhc3N3b3JkXzIwMjQ=",  # base64 of "app_password_2024"
        "url": "jdbc:postgresql://db-prod.corp.local:5432/maindb"
    },
    "mysql-staging": {
        "user": "staging_user",
        "password": "c3RhZ2luZ19wYXNz",  # base64 of "staging_pass"
        "url": "jdbc:mysql://db-staging:3306/appdb"
    }
})

# Robo3T connection JSON
_ROBO3T_JSON = json.dumps({
    "connections": [
        {
            "connectionName": "Production MongoDB",
            "serverHost": "mongo-prod.corp.local",
            "serverPort": 27017,
            "credentials": [
                {
                    "userName": "mongo_admin",
                    "userPassword": "M0ng0Pr0d!2024",
                    "databaseName": "admin"
                }
            ]
        }
    ]
})

# pgAdmin servers.json
_PGADMIN_SERVERS = json.dumps({
    "Servers": {
        "1": {
            "Name": "Production",
            "Group": "Servers",
            "Host": "pg-prod.corp.local",
            "Port": 5432,
            "MaintenanceDB": "postgres",
            "Username": "postgres_admin",
            "SSLMode": "prefer"
        }
    }
})


class TestDBeaverParsing:
    def test_extracts_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dbeaver_dir = Path(tmpdir) / "DBeaverData" / "workspace6" / "General" / ".dbeaver"
            dbeaver_dir.mkdir(parents=True)
            (dbeaver_dir / "credentials-config.json").write_text(_DBEAVER_CREDS)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = DBClientGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            db_creds = [c for c in result.credentials if c.target_application == "DBeaver"]
            assert len(db_creds) >= 2
            usernames = {c.username for c in db_creds}
            assert "app_admin" in usernames
            assert "staging_user" in usernames


class TestRobo3TParsing:
    def test_extracts_mongo_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            robo_dir = Path(tmpdir) / ".3T" / "robo-3t" / "1.4.4"
            robo_dir.mkdir(parents=True)
            (robo_dir / "robo3t.json").write_text(_ROBO3T_JSON)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, user_profile_path=tmpdir,
                appdata_roaming=tmpdir, appdata_local=tmpdir,
            )
            g = DBClientGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            robo_creds = [c for c in result.credentials if c.target_application == "Robo3T"]
            assert len(robo_creds) >= 1
            assert robo_creds[0].username == "mongo_admin"
            assert robo_creds[0].decrypted_value == "M0ng0Pr0d!2024"


class TestPgAdminParsing:
    def test_extracts_server_info(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pgadmin_dir = Path(tmpdir) / "pgAdmin" / "pgadmin4"
            pgadmin_dir.mkdir(parents=True)
            (pgadmin_dir / "servers.json").write_text(_PGADMIN_SERVERS)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = DBClientGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            pg_creds = [c for c in result.credentials if c.target_application == "pgAdmin"]
            assert len(pg_creds) >= 1
            assert pg_creds[0].username == "postgres_admin"


class TestDBClientNoFalsePositives:
    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, user_profile_path=tmpdir,
                appdata_roaming=tmpdir, appdata_local=tmpdir,
            )
            g = DBClientGrabber()
            result = g.execute(gctx)
            assert len(result.credentials) == 0

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dbeaver_dir = Path(tmpdir) / "DBeaverData" / "workspace6" / "General" / ".dbeaver"
            dbeaver_dir.mkdir(parents=True)
            (dbeaver_dir / "credentials-config.json").write_text("not json{{{")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = DBClientGrabber()
            result = g.execute(gctx)
            # Should not crash
            assert result.status == GrabberStatus.COMPLETED
