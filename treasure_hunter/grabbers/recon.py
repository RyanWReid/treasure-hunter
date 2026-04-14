"""
ReconGrabber -- Security product and host configuration reconnaissance

Run this FIRST before other grabbers. Detects:
- Installed AV/EDR products (Defender, CrowdStrike, SentinelOne, etc.)
- UAC level, Credential Guard, RunAsPPL (LSA Protection)
- WDigest plaintext password caching setting
- PowerShell ScriptBlock/Module logging configuration
- Sysmon presence and configuration
- Installed security software from Uninstall registry keys

All information comes from registry reads and process enumeration --
zero OPSEC risk. This is passive reconnaissance.

MITRE ATT&CK: T1518.001 (Security Software Discovery)
"""

from __future__ import annotations

import os
import platform

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


# Known AV/EDR process names
_SECURITY_PROCESSES = {
    "MsMpEng.exe": "Windows Defender",
    "MpCmdRun.exe": "Windows Defender CLI",
    "csfalconservice.exe": "CrowdStrike Falcon",
    "csfalconcontainer.exe": "CrowdStrike Falcon",
    "SentinelAgent.exe": "SentinelOne",
    "SentinelServiceHost.exe": "SentinelOne",
    "CylanceSvc.exe": "Cylance",
    "cb.exe": "Carbon Black",
    "CbDefense.exe": "Carbon Black Defense",
    "RepMgr.exe": "Carbon Black Response",
    "bdagent.exe": "Bitdefender",
    "eset_nod32krn.exe": "ESET NOD32",
    "ekrn.exe": "ESET",
    "savservice.exe": "Sophos",
    "SophosCleanM.exe": "Sophos Clean",
    "hmpalert.exe": "Sophos Intercept X",
    "McShield.exe": "McAfee",
    "mfetp.exe": "McAfee Endpoint",
    "kavtray.exe": "Kaspersky",
    "avp.exe": "Kaspersky",
    "Tanium.exe": "Tanium",
    "TaniumClient.exe": "Tanium",
    "elastic-agent.exe": "Elastic Security",
    "winlogbeat.exe": "Elastic Winlogbeat",
    "osqueryd.exe": "osquery",
    "Sysmon.exe": "Sysmon",
    "Sysmon64.exe": "Sysmon (64-bit)",
    "wazuh-agent.exe": "Wazuh",
    "qualysagent.exe": "Qualys",
}

# Registry paths to check for security configuration
_SECURITY_CHECKS = [
    {
        "name": "UAC Level",
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "values": ["EnableLUA", "ConsentPromptBehaviorAdmin", "FilterAdministratorToken"],
        "hive": "HKLM",
    },
    {
        "name": "Credential Guard",
        "path": r"SYSTEM\CurrentControlSet\Control\LSA",
        "values": ["LsaCfgFlags"],
        "hive": "HKLM",
    },
    {
        "name": "LSA Protection (RunAsPPL)",
        "path": r"SYSTEM\CurrentControlSet\Control\LSA",
        "values": ["RunAsPPL"],
        "hive": "HKLM",
    },
    {
        "name": "WDigest (Plaintext Passwords)",
        "path": r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "values": ["UseLogonCredential"],
        "hive": "HKLM",
    },
    {
        "name": "PowerShell ScriptBlock Logging",
        "path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "values": ["EnableScriptBlockLogging", "EnableScriptBlockInvocationLogging"],
        "hive": "HKLM",
    },
    {
        "name": "PowerShell Module Logging",
        "path": r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "values": ["EnableModuleLogging"],
        "hive": "HKLM",
    },
    {
        "name": "Windows Defender Real-Time Protection",
        "path": r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "values": ["DisableRealtimeMonitoring", "DisableBehaviorMonitoring"],
        "hive": "HKLM",
    },
    {
        "name": "AMSI Providers",
        "path": r"SOFTWARE\Microsoft\AMSI\Providers",
        "values": [],
        "hive": "HKLM",
        "check_exists": True,
    },
]


class ReconGrabber(GrabberModule):
    name = "recon"
    description = "Security product detection and host configuration reconnaissance"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows",)
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        return context.is_windows

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        findings_text = []

        # Detect running security processes
        security_products = self._detect_security_processes()
        if security_products:
            for proc, product in security_products.items():
                findings_text.append(f"[!] {product} detected ({proc})")
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",  # reuse type for recon data
                    target_application="Security Product",
                    username=product,
                    decrypted_value=proc,
                    notes="ACTIVE -- adjust OPSEC accordingly",
                    mitre_technique="T1518.001",
                ))
        else:
            findings_text.append("[+] No known AV/EDR processes detected")

        # Check security registry settings
        registry_findings = self._check_security_registry()
        for finding in registry_findings:
            findings_text.append(finding)

        if findings_text:
            result.findings.append(self.make_finding(
                file_path="[RECON] Security Configuration",
                description=f"Host recon: {len(security_products)} security products, {len(registry_findings)} config checks",
                score=50,
                matched_value="; ".join(f"{p}" for p in security_products.values()) if security_products else "No AV/EDR",
                snippets=findings_text[:20],
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _detect_security_processes() -> dict[str, str]:
        """Check running processes against known security product names."""
        found = {}
        if platform.system() != "Windows":
            return found

        try:
            import ctypes
            import ctypes.wintypes

            # CreateToolhelp32Snapshot + Process32First/Next
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.wintypes.DWORD),
                    ("cntUsage", ctypes.wintypes.DWORD),
                    ("th32ProcessID", ctypes.wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", ctypes.wintypes.DWORD),
                    ("cntThreads", ctypes.wintypes.DWORD),
                    ("th32ParentProcessID", ctypes.wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260),
                ]

            k32 = ctypes.windll.kernel32
            snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snap == -1:
                return found

            try:
                pe = PROCESSENTRY32W()
                pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)

                if k32.Process32FirstW(snap, ctypes.byref(pe)):
                    while True:
                        exe_name = pe.szExeFile
                        if exe_name in _SECURITY_PROCESSES:
                            found[exe_name] = _SECURITY_PROCESSES[exe_name]
                        if not k32.Process32NextW(snap, ctypes.byref(pe)):
                            break
            finally:
                k32.CloseHandle(snap)

        except (AttributeError, OSError):
            pass

        return found

    @staticmethod
    def _check_security_registry() -> list[str]:
        """Check security-relevant registry settings."""
        findings = []
        if platform.system() != "Windows":
            return findings

        try:
            from ._registry import read_reg_value

            for check in _SECURITY_CHECKS:
                hive_name = check["hive"]
                path = check["path"]
                name = check["name"]

                if check.get("check_exists"):
                    # Just check if the key exists
                    try:
                        import winreg
                        hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
                        key = winreg.OpenKey(hive, path)
                        winreg.CloseKey(key)
                        findings.append(f"[i] {name}: present")
                    except (OSError, FileNotFoundError):
                        findings.append(f"[i] {name}: not configured")
                    continue

                for value_name in check["values"]:
                    try:
                        import winreg
                        hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
                        key = winreg.OpenKey(hive, path)
                        val, _ = winreg.QueryValueEx(key, value_name)
                        winreg.CloseKey(key)
                        findings.append(f"[i] {name} / {value_name} = {val}")
                    except (OSError, FileNotFoundError):
                        pass

        except Exception:
            pass

        return findings
