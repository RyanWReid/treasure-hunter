# Integration Testing — Windows Target VM

## Overview

Unit tests validate parsing logic with fixture files. Integration tests validate the full tool against a **real Windows environment** with actual Chrome profiles, registry entries, DPAPI encryption, and file system permissions.

## Infrastructure

**Target**: VM 303 on pve-hack (isolated security lab)
- Windows Server 2022 Evaluation (180-day license, free from Microsoft)
- 4GB RAM, 2 cores, 40GB virtio disk
- Network: victim bridge (10.99.98.0/24) — isolated from LAN
- Windows Defender disabled (will flag the tool)

Windows Server has identical credential stores to Win10/11 (Chrome, registry,
DPAPI, etc.) and Microsoft provides a direct-download ISO that works with wget.

## Setup Steps

### 1. Download Windows Server 2022 ISO

```bash
# On pve-hack — direct wget link (no browser required)
wget -O /var/lib/vz/template/iso/winserver-eval.iso \
  "https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso"

# Also download VirtIO drivers
wget -O /var/lib/vz/template/iso/virtio-win.iso \
  "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
```

### 2. Create VM 303

```bash
# On pve-hack shell (already done if using setup-treasure-target.sh)
qm create 303 \
  --name treasure-target \
  --memory 4096 \
  --cores 2 \
  --sockets 1 \
  --ostype win11 \
  --net0 virtio,bridge=vmbr2 \
  --scsihw virtio-scsi-single \
  --scsi0 local-lvm:40,ssd=1 \
  --ide0 local:iso/virtio-win.iso,media=cdrom \
  --ide2 local:iso/winserver-eval.iso,media=cdrom \
  --boot order='ide2;scsi0' \
  --agent 1 \
  --machine q35 \
  --cpu host
```

### 3. Install Windows Server

1. Boot VM 303, start Windows installer
2. Select **"Windows Server 2022 Standard Evaluation (Desktop Experience)"**
3. When it can't find disk: Load driver → browse virtio CD → vioscsi\w11\amd64
4. Install normally (set a local admin password)
5. After install: install VirtIO guest agent + network driver from the IDE0 CD
6. Set IP: `10.99.98.50/24` (no gateway — isolated)

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

## Network Testing (from wraith/Kali)

After local testing, test network scanning from the attack network:
```bash
# On wraith (10.99.99.20)
# First enable SMB shares on the Windows VM
treasure-hunter --network 10.99.98.50 -o network-results.jsonl
```
