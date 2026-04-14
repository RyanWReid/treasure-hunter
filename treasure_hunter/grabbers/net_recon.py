"""
NetReconGrabber -- Network reconnaissance for lateral movement planning

Enumerates the target's network state to identify:
- ARP table (recently contacted hosts -- lateral movement targets)
- DNS cache (recently resolved hostnames -- reveals internal services)
- Active TCP connections (connected hosts + services)
- Listening ports (running services on this host)

Windows: Uses iphlpapi.dll via ctypes (GetIpNetTable, GetExtendedTcpTable, etc.)
Linux: Parses /proc/net/arp, /proc/net/tcp

MITRE ATT&CK: T1016 (System Network Configuration Discovery),
              T1049 (System Network Connections Discovery)
"""

from __future__ import annotations

import os
import platform
import re
import socket
import struct

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


class NetReconGrabber(GrabberModule):
    name = "net_recon"
    description = "Network recon: ARP table, DNS cache, TCP connections, listening ports"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        return True  # Network info is always available

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        recon_data = []

        # ARP table
        arp_entries = self._get_arp_table()
        if arp_entries:
            recon_data.append(f"ARP table: {len(arp_entries)} entries")
            for entry in arp_entries[:50]:
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application="ARP Table",
                    url=entry["ip"],
                    username=entry["mac"],
                    notes=f"interface={entry.get('iface', '')}",
                    mitre_technique="T1016",
                ))

        # TCP connections
        tcp_conns = self._get_tcp_connections()
        if tcp_conns:
            # Filter to interesting connections (not localhost)
            remote_conns = [c for c in tcp_conns
                          if c["remote_ip"] not in ("127.0.0.1", "0.0.0.0", "::1", "::")]
            if remote_conns:
                recon_data.append(f"Active connections: {len(remote_conns)} remote")
                for conn in remote_conns[:30]:
                    result.credentials.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="token",
                        target_application="TCP Connection",
                        url=f"{conn['remote_ip']}:{conn['remote_port']}",
                        username=f"pid={conn.get('pid', '?')}",
                        notes=f"state={conn.get('state', '')}; local={conn.get('local_port', '')}",
                        mitre_technique="T1049",
                    ))

        # Listening ports
        listeners = self._get_listening_ports()
        if listeners:
            recon_data.append(f"Listening ports: {len(listeners)}")
            for listener in listeners[:20]:
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application="Listening Service",
                    url=f"0.0.0.0:{listener['port']}",
                    username=f"pid={listener.get('pid', '?')}",
                    notes=f"protocol=TCP",
                    mitre_technique="T1049",
                ))

        # DNS cache (Windows only)
        if platform.system() == "Windows":
            dns_entries = self._get_dns_cache_windows()
            if dns_entries:
                recon_data.append(f"DNS cache: {len(dns_entries)} entries")
                for entry in dns_entries[:30]:
                    result.credentials.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="token",
                        target_application="DNS Cache",
                        url=entry["name"],
                        username=entry.get("ip", ""),
                        notes=f"type={entry.get('type', 'A')}",
                        mitre_technique="T1016",
                    ))

        if recon_data:
            result.findings.append(self.make_finding(
                file_path="[NET] Network Reconnaissance",
                description=f"Network recon: {'; '.join(recon_data)}",
                score=75,
                matched_value=f"{len(arp_entries)} hosts in ARP",
                snippets=recon_data,
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _get_arp_table() -> list[dict]:
        """Get ARP table entries."""
        entries = []

        if platform.system() == "Windows":
            try:
                import ctypes
                import ctypes.wintypes

                iphlpapi = ctypes.windll.iphlpapi

                # GetIpNetTable
                size = ctypes.c_ulong(0)
                iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
                buf = (ctypes.c_byte * size.value)()
                ret = iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False)

                if ret == 0:
                    num_entries = struct.unpack_from("I", bytes(buf), 0)[0]
                    offset = 4
                    for i in range(min(num_entries, 100)):
                        # MIB_IPNETROW: index(4), addr(4), phys_addr_len(4), phys_addr(8), type(4)
                        if offset + 24 > len(buf):
                            break
                        row = bytes(buf[offset:offset + 24])
                        ip_bytes = row[4:8]
                        ip = f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}"
                        mac_len = struct.unpack_from("I", row, 8)[0]
                        mac_bytes = row[12:12 + min(mac_len, 6)]
                        mac = ":".join(f"{b:02x}" for b in mac_bytes)

                        if ip != "0.0.0.0":
                            entries.append({"ip": ip, "mac": mac, "iface": ""})
                        offset += 24

            except (AttributeError, OSError):
                pass

        elif platform.system() == "Linux":
            try:
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:  # skip header
                        parts = line.split()
                        if len(parts) >= 4:
                            entries.append({
                                "ip": parts[0],
                                "mac": parts[3],
                                "iface": parts[-1] if len(parts) >= 6 else "",
                            })
            except OSError:
                pass

        elif platform.system() == "Darwin":
            # macOS: parse arp -an output style from /proc alternative
            try:
                import subprocess
                out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=5)
                for line in out.stdout.splitlines():
                    match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)", line)
                    if match:
                        entries.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "iface": "",
                        })
            except (OSError, subprocess.TimeoutExpired):
                pass

        return entries

    @staticmethod
    def _get_tcp_connections() -> list[dict]:
        """Get active TCP connections."""
        connections = []

        if platform.system() == "Linux":
            try:
                with open("/proc/net/tcp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        local = parts[1]
                        remote = parts[2]
                        state_hex = parts[3]

                        def parse_addr(addr):
                            ip_hex, port_hex = addr.split(":")
                            ip_int = int(ip_hex, 16)
                            ip = socket.inet_ntoa(struct.pack("<I", ip_int))
                            port = int(port_hex, 16)
                            return ip, port

                        local_ip, local_port = parse_addr(local)
                        remote_ip, remote_port = parse_addr(remote)
                        state_map = {"01": "ESTABLISHED", "0A": "LISTEN", "06": "TIME_WAIT"}
                        state = state_map.get(state_hex, state_hex)

                        connections.append({
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "state": state,
                            "pid": "",
                        })
            except OSError:
                pass

        elif platform.system() == "Windows":
            try:
                import ctypes

                iphlpapi = ctypes.windll.iphlpapi

                # GetExtendedTcpTable with TCP_TABLE_OWNER_PID_ALL
                size = ctypes.c_ulong(0)
                iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)
                buf = (ctypes.c_byte * size.value)()
                ret = iphlpapi.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 5, 0)

                if ret == 0:
                    data = bytes(buf)
                    num_entries = struct.unpack_from("I", data, 0)[0]
                    offset = 4
                    # MIB_TCPROW_OWNER_PID: state(4), localAddr(4), localPort(4),
                    # remoteAddr(4), remotePort(4), pid(4) = 24 bytes
                    for i in range(min(num_entries, 200)):
                        if offset + 24 > len(data):
                            break
                        row = data[offset:offset + 24]
                        state = struct.unpack_from("I", row, 0)[0]
                        local_ip = socket.inet_ntoa(row[4:8])
                        local_port = struct.unpack(">H", row[8:10])[0]
                        remote_ip = socket.inet_ntoa(row[12:16])
                        remote_port = struct.unpack(">H", row[16:18])[0]
                        pid = struct.unpack_from("I", row, 20)[0]

                        state_map = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT",
                                    4: "SYN_RECV", 5: "ESTABLISHED", 6: "FIN_WAIT1",
                                    7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING",
                                    10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}

                        connections.append({
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "state": state_map.get(state, str(state)),
                            "pid": str(pid),
                        })
                        offset += 24
            except (AttributeError, OSError):
                pass

        return connections

    @staticmethod
    def _get_listening_ports() -> list[dict]:
        """Get listening TCP ports."""
        connections = NetReconGrabber._get_tcp_connections()
        return [c for c in connections
                if c.get("state") in ("LISTEN", "0A", 2)
                and c["local_ip"] != "127.0.0.1"]

    @staticmethod
    def _get_dns_cache_windows() -> list[dict]:
        """Get DNS cache entries on Windows via DnsGetCacheDataTable."""
        entries = []
        try:
            import ctypes

            class DNS_CACHE_ENTRY(ctypes.Structure):
                pass
            DNS_CACHE_ENTRY._fields_ = [
                ("pNext", ctypes.POINTER(DNS_CACHE_ENTRY)),
                ("pszName", ctypes.c_wchar_p),
                ("wType", ctypes.c_ushort),
                ("wDataLength", ctypes.c_ushort),
                ("dwFlags", ctypes.c_ulong),
            ]

            dnsapi = ctypes.windll.dnsapi
            head = ctypes.POINTER(DNS_CACHE_ENTRY)()

            ret = dnsapi.DnsGetCacheDataTable(ctypes.byref(head))
            if not ret:
                return entries

            current = head
            count = 0
            while current and count < 200:
                entry = current.contents
                name = entry.pszName or ""
                record_type = entry.wType
                type_map = {1: "A", 5: "CNAME", 28: "AAAA", 33: "SRV", 12: "PTR"}

                if name and not name.startswith(".."):
                    entries.append({
                        "name": name,
                        "type": type_map.get(record_type, str(record_type)),
                        "ip": "",  # Full resolution requires DnsQuery
                    })

                current = entry.pNext
                count += 1

        except (AttributeError, OSError):
            pass

        return entries
