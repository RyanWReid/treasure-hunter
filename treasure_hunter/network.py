"""
NETWORK SHARE SCANNER — Enumerate and crawl SMB shares

Discovers accessible network shares and feeds them into the scanning engine.
This is the key differentiator from local-only tools — corporate file servers
are where the most valuable data lives.

Discovery methods:
- Windows: NetShareEnum via ctypes (enumerate shares on a target)
- Windows: WNetEnumResource via ctypes (enumerate mapped drives)
- Cross-platform: Direct UNC/SMB path probing

Usage:
    treasure-hunter --network 10.0.0.0/24       # Scan a subnet
    treasure-hunter --network dc01.corp.local    # Scan specific server
    treasure-hunter --network auto               # Auto-discover via mapped drives

MITRE ATT&CK: T1135 (Network Share Discovery), T1039 (Data from Network Shared Drive)
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

logger = logging.getLogger(__name__)


def enumerate_network_targets(target_spec: str) -> list[str]:
    """Parse target specification into a list of hostnames/IPs.

    Supports:
    - "auto" — discover from mapped drives and recent connections
    - "10.0.0.1" — single host
    - "10.0.0.0/24" — CIDR subnet
    - "dc01.corp.local" — hostname
    - "10.0.0.1,10.0.0.2" — comma-separated list
    """
    if target_spec.lower() == "auto":
        return _auto_discover_hosts()

    targets = []
    for part in target_spec.split(","):
        part = part.strip()
        if "/" in part and re.match(r"\d+\.\d+\.\d+\.\d+/\d+", part):
            targets.extend(_expand_cidr(part))
        else:
            targets.append(part)

    return targets


def enumerate_shares(host: str, timeout: float = 5.0) -> list[str]:
    """Enumerate accessible SMB shares on a host.

    Returns list of UNC paths (e.g., \\\\host\\share).
    """
    if platform.system() == "Windows":
        return _enumerate_shares_windows(host)
    else:
        return _enumerate_shares_probe(host, timeout)


def discover_network_paths(target_spec: str, max_workers: int = 8,
                           timeout: float = 5.0) -> list[str]:
    """Full network discovery pipeline.

    Takes a target spec, enumerates hosts, discovers shares, and returns
    a list of accessible UNC paths ready for the scanner.
    """
    hosts = enumerate_network_targets(target_spec)
    if not hosts:
        logger.warning("No network targets found")
        return []

    logger.info(f"Probing {len(hosts)} host(s) for accessible shares")

    all_paths = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(enumerate_shares, host, timeout): host for host in hosts}
        for future in as_completed(futures):
            host = futures[future]
            try:
                shares = future.result()
                all_paths.extend(shares)
                if shares:
                    logger.info(f"Found {len(shares)} share(s) on {host}")
            except Exception as e:
                logger.debug(f"Failed to enumerate {host}: {e}")

    logger.info(f"Total accessible shares: {len(all_paths)}")
    return all_paths


# --- Windows-specific enumeration ---

def _enumerate_shares_windows(host: str) -> list[str]:
    """Use NetShareEnum via ctypes to enumerate SMB shares on Windows."""
    try:
        import ctypes
        import ctypes.wintypes

        class SHARE_INFO_1(ctypes.Structure):
            _fields_ = [
                ("shi1_netname", ctypes.c_wchar_p),
                ("shi1_type", ctypes.wintypes.DWORD),
                ("shi1_remark", ctypes.c_wchar_p),
            ]

        netapi32 = ctypes.windll.Netapi32
        buf = ctypes.c_void_p()
        entries_read = ctypes.wintypes.DWORD()
        total_entries = ctypes.wintypes.DWORD()
        resume_handle = ctypes.wintypes.DWORD(0)

        result = netapi32.NetShareEnum(
            host,  # servername
            1,  # level (SHARE_INFO_1)
            ctypes.byref(buf),
            0xFFFFFFFF,  # MAX_PREFERRED_LENGTH
            ctypes.byref(entries_read),
            ctypes.byref(total_entries),
            ctypes.byref(resume_handle),
        )

        shares = []
        if result == 0 and buf.value:  # NERR_Success
            share_array = ctypes.cast(buf, ctypes.POINTER(SHARE_INFO_1 * entries_read.value))
            for i in range(entries_read.value):
                share = share_array.contents[i]
                # Filter out admin/IPC shares unless they're disk shares
                share_type = share.shi1_type & 0xFF
                if share_type == 0:  # STYPE_DISKTREE
                    name = share.shi1_netname
                    if name and not name.endswith("$"):
                        unc = f"\\\\{host}\\{name}"
                        shares.append(unc)

            netapi32.NetApiBufferFree(buf)

        return shares

    except (AttributeError, OSError) as e:
        logger.debug(f"NetShareEnum failed for {host}: {e}")
        return _enumerate_shares_probe(host)


def _enumerate_shares_probe(host: str, timeout: float = 5.0) -> list[str]:
    """Probe common share names when NetShareEnum isn't available."""
    # First check if SMB port is open
    if not _is_port_open(host, 445, timeout):
        return []

    common_shares = [
        "SYSVOL", "NETLOGON", "Users", "Shared", "Public",
        "Data", "IT", "Finance", "HR", "Legal", "Engineering",
        "Marketing", "Sales", "Backup", "Backups", "Archive",
        "Home", "Profiles", "Software", "Tools", "Temp",
        "Projects", "Development", "Docs", "Documents",
    ]

    accessible = []
    for share_name in common_shares:
        unc_path = f"\\\\{host}\\{share_name}"
        # On Windows, try to access; on Unix, just record the path
        if platform.system() == "Windows":
            if os.path.exists(unc_path):
                accessible.append(unc_path)
        else:
            # Can't test SMB access from Unix without smbclient
            # Record as potential target
            accessible.append(unc_path)

    return accessible


def _auto_discover_hosts() -> list[str]:
    """Auto-discover network hosts from mapped drives, ARP cache, DNS."""
    hosts = set()

    # Mapped network drives (Windows)
    if platform.system() == "Windows":
        for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    import ctypes
                    buf = ctypes.create_unicode_buffer(260)
                    result = ctypes.windll.mpr.WNetGetConnectionW(f"{letter}:", buf, ctypes.byref(ctypes.c_ulong(260)))
                    if result == 0:
                        unc = buf.value  # e.g., \\server\share
                        match = re.match(r"\\\\([^\\]+)", unc)
                        if match:
                            hosts.add(match.group(1))
                except (AttributeError, OSError):
                    pass

    # Recent UNC paths from environment
    for env_var in ("LOGONSERVER",):
        server = os.environ.get(env_var, "")
        if server:
            server = server.strip("\\")
            if server:
                hosts.add(server)

    # DNS domain controller lookup
    domain = os.environ.get("USERDNSDOMAIN", "")
    if domain:
        try:
            # SRV record for domain controllers
            dc_host = socket.getfqdn(f"dc.{domain}")
            if dc_host and dc_host != f"dc.{domain}":
                hosts.add(dc_host)
        except (socket.error, OSError):
            pass

    return list(hosts)


def _expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR notation to list of host IPs (skip network/broadcast)."""
    try:
        ip_str, prefix_str = cidr.split("/")
        prefix_len = int(prefix_str)
        if prefix_len < 16 or prefix_len > 30:
            logger.warning(f"CIDR prefix {prefix_len} out of safe range (16-30)")
            return []

        parts = [int(p) for p in ip_str.split(".")]
        ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network = ip_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)

        hosts = []
        for addr in range(network + 1, broadcast):
            hosts.append(f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}")

        return hosts

    except (ValueError, IndexError):
        return [cidr]


def _is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Quick TCP connect check."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except (socket.error, OSError):
        return False
