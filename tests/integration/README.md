# Integration Testing -- Windows Target VM

## Overview

Unit tests validate parsing logic with fixture files. Integration tests validate the full tool against a **real Windows environment** with actual Chrome profiles, registry entries, DPAPI encryption, and file system permissions.

## Infrastructure

**Target**: An isolated Windows VM on a separate network segment
- Windows Server 2022 Evaluation (180-day license, free from Microsoft)
- 4GB RAM, 2 cores, 40GB virtio disk
- Network: isolated bridge -- no route to production LAN
- Windows Defender disabled (will flag the tool)

Windows Server has identical credential stores to Win10/11 (Chrome, registry,
DPAPI, etc.) and Microsoft provides a direct-download ISO that works with wget.

## Setup Steps

### 1. Download Windows Server 2022 ISO

```bash
wget -O /path/to/iso/winserver-eval.iso \
  "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"

# Also download VirtIO drivers
wget -O /path/to/iso/virtio-win.iso \
  "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
```

### 2. Create the VM

Create a VM with your hypervisor of choice (Proxmox, Hyper-V, VMware, etc.) using:
- 4GB RAM, 2 cores
- VirtIO disk + network
- Both ISOs attached as CD drives
- **Isolated network** -- do not bridge to production

### 3. Install Windows Server

1. Boot VM, start Windows installer
2. Select **"Windows Server 2022 Standard Evaluation (Desktop Experience)"**
3. When it can't find disk: Load driver -> browse virtio CD -> vioscsi\w11\amd64
4. Install normally (set a local admin password)
5. After install: install VirtIO guest agent + network driver from the CD
6. Set a static IP on your isolated test network

### 4. Disable Defender

```powershell
# Run as Administrator
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableScriptScanning $true
# Permanent (requires Tamper Protection off in GUI first):
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

### 5. Run Seeding Script

Copy `seed_target.ps1` to the VM and run as Administrator:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\seed_target.ps1
```

### 6. Copy Treasure Hunter

Either build the .exe and copy via SMB, or install Python and run directly:
```powershell
# Option A: Pre-built exe (from GitHub Actions release)
# Copy treasure-hunter.exe to C:\Tools\

# Option B: Run from source
# Install Python 3.12, then:
pip install -e C:\Tools\treasure-hunter
```

### 7. Run Full Scan

```powershell
cd C:\Tools
treasure-hunter.exe -p full -o results.jsonl --html report.html
```

### 8. Run Validation

```powershell
python validate_windows.py results.jsonl
```

## Network Testing

After local testing, test network scanning from a separate attack machine:
```bash
# From your attack box on the same isolated network
treasure-hunter --network <TARGET_IP> -o network-results.jsonl
```
