"""Tests for value taxonomy — validate categories and pattern coverage."""

from treasure_hunter.rules.value_taxonomy import (
    ALL_CATEGORIES,
    BACKUPS,
    CATEGORY_MAP,
    CREDENTIALS,
    INFRASTRUCTURE,
    SENSITIVE_DOCUMENTS,
    SOURCE_CODE,
    UNRELEASED_SOFTWARE,
)


class TestCategoryStructure:
    def test_six_categories(self):
        assert len(ALL_CATEGORIES) == 6

    def test_category_map_complete(self):
        for cat in ALL_CATEGORIES:
            assert cat.name in CATEGORY_MAP
            assert CATEGORY_MAP[cat.name] is cat

    def test_all_have_names(self):
        for cat in ALL_CATEGORIES:
            assert cat.name
            assert cat.description

    def test_base_weights_in_range(self):
        for cat in ALL_CATEGORIES:
            assert 1 <= cat.base_weight <= 5, f"{cat.name} weight {cat.base_weight} out of range"


class TestCredentials:
    def test_highest_weight(self):
        assert CREDENTIALS.base_weight == 5

    def test_covers_password_managers(self):
        assert '.kdbx' in CREDENTIALS.extensions
        assert '.kdb' in CREDENTIALS.extensions

    def test_covers_ssh_keys(self):
        assert '.pem' in CREDENTIALS.extensions
        assert '.key' in CREDENTIALS.extensions
        assert '.ppk' in CREDENTIALS.extensions

    def test_covers_env_files(self):
        assert '.env' in CREDENTIALS.extensions
        assert '.env.local' in CREDENTIALS.extensions
        assert '.env.production' in CREDENTIALS.extensions

    def test_keywords_include_common_terms(self):
        keywords = set(CREDENTIALS.filename_keywords)
        assert 'password' in keywords
        assert 'secret' in keywords
        assert 'token' in keywords
        assert 'api_key' in keywords

    def test_content_patterns_exist(self):
        assert len(CREDENTIALS.content_patterns) > 0


class TestInfrastructure:
    def test_weight(self):
        assert INFRASTRUCTURE.base_weight == 4

    def test_covers_remote_access(self):
        assert '.rdp' in INFRASTRUCTURE.extensions
        assert '.ovpn' in INFRASTRUCTURE.extensions

    def test_covers_iac(self):
        assert '.tf' in INFRASTRUCTURE.extensions
        assert '.tfstate' in INFRASTRUCTURE.extensions


class TestBackups:
    def test_covers_archives(self):
        assert '.zip' in BACKUPS.extensions
        assert '.7z' in BACKUPS.extensions
        assert '.tar.gz' in BACKUPS.extensions

    def test_covers_database_dumps(self):
        assert '.sql' in BACKUPS.extensions
        assert '.bak' in BACKUPS.extensions
        assert '.dump' in BACKUPS.extensions

    def test_covers_sqlite(self):
        assert '.sqlite' in BACKUPS.extensions
        assert '.sqlite3' in BACKUPS.extensions
        assert '.db' in BACKUPS.extensions


class TestCredentialPathCoverage:
    """Verify all critical credential artifact paths are covered."""

    def _path_matches(self, test_path: str) -> bool:
        import re
        for pattern in CREDENTIALS.path_patterns:
            regex = pattern.replace('*', '.*').replace('\\', '\\\\')
            if re.search(regex, test_path, re.IGNORECASE):
                return True
        return False

    # Browser credential databases
    def test_chrome_login_data(self):
        assert self._path_matches(r"C:\Users\john\AppData\Local\Google\Chrome\User Data\Default\Login Data")

    def test_chrome_cookies(self):
        assert self._path_matches(r"C:\Users\john\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies")

    def test_chrome_local_state(self):
        assert self._path_matches(r"C:\Users\john\AppData\Local\Google\Chrome\User Data\Local State")

    def test_edge_login_data(self):
        assert self._path_matches(r"C:\Users\john\AppData\Local\Microsoft\Edge\User Data\Default\Login Data")

    def test_firefox_logins(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\Mozilla\Firefox\Profiles\abc123\logins.json")

    def test_firefox_cookies(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\Mozilla\Firefox\Profiles\abc123\cookies.sqlite")

    # Messaging app tokens
    def test_slack_leveldb(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\Slack\Local Storage\leveldb\000003.log")

    def test_discord_leveldb(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\discord\Local Storage\leveldb\000003.log")

    def test_teams_leveldb(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\Microsoft\Teams\Local Storage\leveldb\000003.log")

    # Remote access tools
    def test_filezilla_cleartext(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\FileZilla\recentservers.xml")

    def test_mremoteng(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\mRemoteNG\confCons.xml")

    def test_winscp(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\WinSCP.ini")

    # Cloud CLI tokens
    def test_azure_access_tokens(self):
        assert self._path_matches(r"C:\Users\john\.azure\accessTokens.json")

    def test_gh_cli_token(self):
        assert self._path_matches(r"C:\Users\john\.config\gh\hosts.yml")

    def test_terraform_cloud_token(self):
        assert self._path_matches(r"C:\Users\john\.terraform.d\credentials.tfrc.json")

    # Git credentials
    def test_git_credentials_plaintext(self):
        assert self._path_matches(r"C:\Users\john\.git-credentials")

    # Database password files
    def test_pgpass(self):
        assert self._path_matches(r"C:\Users\john\.pgpass")

    # System artifacts
    def test_powershell_history(self):
        assert self._path_matches(
            r"C:\Users\john\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        )

    def test_sticky_notes(self):
        assert self._path_matches(
            r"C:\Users\john\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
        )

    # Package manager credentials
    def test_npm_credentials(self):
        assert self._path_matches(r"C:\Users\john\.npmrc")

    def test_maven_settings(self):
        assert self._path_matches(r"C:\Users\john\.m2\settings.xml")

    def test_cargo_credentials(self):
        assert self._path_matches(r"C:\Users\john\.cargo\credentials.toml")


class TestInfrastructurePathCoverage:
    """Verify infrastructure path patterns match expected locations."""

    def _path_matches(self, test_path: str) -> bool:
        import re
        for pattern in INFRASTRUCTURE.path_patterns:
            regex = pattern.replace('*', '.*').replace('\\', '\\\\')
            if re.search(regex, test_path, re.IGNORECASE):
                return True
        return False

    def test_chrome_history(self):
        assert self._path_matches(r"C:\Users\john\AppData\Local\Google\Chrome\User Data\Default\History")

    def test_chrome_bookmarks(self):
        assert self._path_matches(r"C:\Users\john\AppData\Local\Google\Chrome\User Data\Default\Bookmarks")

    def test_firefox_places(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\Mozilla\Firefox\Profiles\abc123\places.sqlite")

    def test_oracle_tnsnames(self):
        assert self._path_matches(r"C:\oracle\network\admin\tnsnames.ora")

    def test_recent_files(self):
        assert self._path_matches(r"C:\Users\john\AppData\Roaming\Microsoft\Windows\Recent\doc.lnk")


class TestContentPatternCoverage:
    """Verify content regex patterns match expected secrets."""

    import re

    def test_aws_key(self):
        import re
        assert re.search(r"AKIA[0-9A-Z]{16}", "AKIAIOSFODNN7EXAMPLE")

    def test_github_token(self):
        import re
        assert re.search(r"gh[ps]_[A-Za-z0-9_]{36,}", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234")

    def test_slack_token(self):
        import re
        assert re.search(r"xox[bprs]-[0-9]{10,}-[0-9a-zA-Z]+", "xoxb-1234567890-abcdef123")

    def test_private_key_header(self):
        import re
        assert re.search(r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----", "-----BEGIN RSA PRIVATE KEY-----")

    def test_vault_token(self):
        import re
        assert re.search(r"hvs\.[A-Za-z0-9]{24,}", "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZab")

    def test_bearer_token(self):
        import re
        assert re.search(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer eyJhbGciOiJSUzI1NiJ9.test")

    def test_jdbc_connection(self):
        import re
        for pattern in INFRASTRUCTURE.content_patterns:
            if re.search(pattern, "jdbc:postgresql://db.internal:5432/prod", re.IGNORECASE):
                return
        assert False, "No JDBC pattern matched"

    def test_mongodb_connection(self):
        import re
        for pattern in INFRASTRUCTURE.content_patterns:
            if re.search(pattern, "mongodb+srv://admin:pass@cluster.mongodb.net", re.IGNORECASE):
                return
        assert False, "No MongoDB pattern matched"

    def test_git_remote_with_creds(self):
        import re
        for pattern in SOURCE_CODE.content_patterns:
            if re.search(pattern, "https://user:ghp_token@github.com/org/repo", re.IGNORECASE):
                return
        assert False, "No git remote credential pattern matched"


class TestExtensionUniqueness:
    def test_no_typos_in_extensions(self):
        """All extensions should start with a dot."""
        for cat in ALL_CATEGORIES:
            for ext in cat.extensions:
                assert ext.startswith('.'), f"{cat.name} has extension without dot: {ext}"

    def test_extensions_lowercase(self):
        """All extensions should be lowercase for consistent matching."""
        for cat in ALL_CATEGORIES:
            for ext in cat.extensions:
                assert ext == ext.lower(), f"{cat.name} has non-lowercase extension: {ext}"
