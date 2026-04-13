# Rubber Ducky / USB HID Payloads

DuckyScript payloads for deploying treasure-hunter via USB HID attack devices (Hak5 Rubber Ducky, O.MG Cable, Flipper Zero BadUSB, etc.).

## Payloads

| Payload | Description | Duration | OPSEC |
|---------|-------------|----------|-------|
| `smash-grab.dd` | Fast smash-and-grab to USB storage | ~10s type + 5m scan | Low |
| `stealth-exfil.dd` | Hidden window, encrypt output, eject | ~10s type + 5m scan | High |
| `network-spray.dd` | Scan + lateral movement | ~10s type + 10m scan | Medium |

## Prerequisites

1. Build `treasure-hunter.exe` (8.2 MB) via PyInstaller:
   ```
   pip install pyinstaller
   pyinstaller --onefile --name treasure-hunter --console treasure_hunter/__main__.py
   ```

2. Copy `dist/treasure-hunter.exe` to the Ducky's mass storage as `D:\treasure-hunter.exe`

3. Compile the `.dd` payload for your device

## Device Setup

### Hak5 Rubber Ducky (USB-A)
- Copy `treasure-hunter.exe` to MicroSD root
- Compile `.dd` to `inject.bin` using DuckEncoder
- MicroSD: `inject.bin` + `treasure-hunter.exe`

### O.MG Cable
- Upload payload via O.MG web interface
- Stage `treasure-hunter.exe` on the cable's mass storage

### Flipper Zero (BadUSB)
- Convert `.dd` to Flipper BadUSB format
- Stage exe via separate USB or network download

## Notes

- All payloads assume the USB device mounts as drive `D:\`
- Adjust drive letter in the payload if your device mounts differently
- The `DELAY` values are conservative -- reduce for faster machines
- `--encrypt` requires a passphrase -- change it from the default before deployment
