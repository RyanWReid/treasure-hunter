#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Seeds a Windows test VM with fake credentials for treasure-hunter validation.

.DESCRIPTION
    Creates realistic credential artifacts across all locations that
    treasure-hunter's 16 grabber modules target. Every artifact uses
    FAKE credentials — safe for testing.

    Run this ONCE after Windows is installed and Defender is disabled.

.NOTES
    Target: VM 303 (treasure-target) on pve-hack victim network
    All credentials are FAKE — do not use on production systems
#>

Write-Host "=== Treasure Hunter Target Seeding ===" -ForegroundColor Cyan
Write-Host "Planting fake credentials for integration testing...`n"

$ErrorActionPreference = "Continue"
$home_dir = $env:USERPROFILE

# ---------------------------------------------------------------
# 1. AWS CLI Credentials
# ---------------------------------------------------------------
Write-Host "[1/16] AWS credentials..." -ForegroundColor Yellow
$aws_dir = "$home_dir\.aws"
New-Item -ItemType Directory -Path $aws_dir -Force | Out-Null

@"
[default]
aws_access_key_id = AKIATEST1234567FAKE
aws_secret_access_key = FakeSecretKey+TestOnly/DoNotUse123456789
region = us-east-1

[production]
aws_access_key_id = AKIAPROD9876543FAKE
aws_secret_access_key = ProdFakeKey+TestOnly/NeverReal98765432
aws_session_token = FakeSessionToken+TestOnly+Base64EncodedStuff
"@ | Set-Content "$aws_dir\credentials" -Encoding UTF8

@"
[default]
region = us-east-1
output = json

[profile production]
role_arn = arn:aws:iam::123456789012:role/AdminRole
source_profile = default
"@ | Set-Content "$aws_dir\config" -Encoding UTF8

# ---------------------------------------------------------------
# 2. Git Credentials
# ---------------------------------------------------------------
Write-Host "[2/16] Git credentials..." -ForegroundColor Yellow
@"
https://testuser:ghp_FAKE1234567890abcdefghijklmnopqr@github.com
https://deploy:glpat-FAKEtokenForGitLab1234567@gitlab.com
"@ | Set-Content "$home_dir\.git-credentials" -Encoding UTF8

# Create a fake repo with embedded creds
$repo_dir = "$home_dir\Projects\internal-app\.git"
New-Item -ItemType Directory -Path $repo_dir -Force | Out-Null
@"
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://deployer:ghp_FakeDeployToken12345@github.com/corp/internal-api.git
    fetch = +refs/heads/*:refs/remotes/origin/*
"@ | Set-Content "$repo_dir\config" -Encoding UTF8

# ---------------------------------------------------------------
# 3. FileZilla (base64 cleartext passwords)
# ---------------------------------------------------------------
Write-Host "[3/16] FileZilla configs..." -ForegroundColor Yellow
$fz_dir = "$env:APPDATA\FileZilla"
New-Item -ItemType Directory -Path $fz_dir -Force | Out-Null

$fz_pass1 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("FtpPassword123!"))
$fz_pass2 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("BackupServerPass"))

@"
<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.66.5" platform="windows">
  <RecentServers>
    <Server>
      <Host>ftp.corp-internal.test</Host>
      <Port>22</Port>
      <Protocol>1</Protocol>
      <Type>0</Type>
      <User>deploy</User>
      <Pass encoding="base64">$fz_pass1</Pass>
    </Server>
    <Server>
      <Host>backup.datacenter.test</Host>
      <Port>21</Port>
      <Protocol>0</Protocol>
      <Type>0</Type>
      <User>backup_admin</User>
      <Pass encoding="base64">$fz_pass2</Pass>
    </Server>
    <Server>
      <Host>dev.staging.test</Host>
      <Port>2222</Port>
      <Protocol>1</Protocol>
      <Type>0</Type>
      <User>developer</User>
      <Pass encoding="base64">$(  [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("DevStagingPass!")))</Pass>
    </Server>
  </RecentServers>
</FileZilla3>
"@ | Set-Content "$fz_dir\recentservers.xml" -Encoding UTF8

# ---------------------------------------------------------------
# 4. PuTTY Sessions (registry)
# ---------------------------------------------------------------
Write-Host "[4/16] PuTTY sessions..." -ForegroundColor Yellow
$putty_base = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
New-Item -Path $putty_base -Force | Out-Null

@("db-server-prod", "web-01-staging", "jump-box-dc") | ForEach-Object {
    $session_path = "$putty_base\$_"
    New-Item -Path $session_path -Force | Out-Null
    Set-ItemProperty -Path $session_path -Name "HostName" -Value "$_.corp-internal.test"
    Set-ItemProperty -Path $session_path -Name "UserName" -Value "admin"
    Set-ItemProperty -Path $session_path -Name "PortNumber" -Value 22 -Type DWord
    Set-ItemProperty -Path $session_path -Name "Protocol" -Value "ssh"
}

# ---------------------------------------------------------------
# 5. Windows AutoLogon (registry)
# ---------------------------------------------------------------
Write-Host "[5/16] Windows AutoLogon..." -ForegroundColor Yellow
$winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $winlogon -Name "DefaultUserName" -Value "svc_backup"
Set-ItemProperty -Path $winlogon -Name "DefaultPassword" -Value "FakeAutoLogon!2024"
Set-ItemProperty -Path $winlogon -Name "DefaultDomainName" -Value "CORP"

# ---------------------------------------------------------------
# 6. SSH Keys
# ---------------------------------------------------------------
Write-Host "[6/16] SSH keys..." -ForegroundColor Yellow
$ssh_dir = "$home_dir\.ssh"
New-Item -ItemType Directory -Path $ssh_dir -Force | Out-Null

@"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
FAKE_KEY_DATA_FOR_TESTING_ONLY_DO_NOT_USE_IN_PRODUCTION_SYSTEMS
THIS_IS_NOT_A_REAL_PRIVATE_KEY_IT_IS_FOR_TESTING_TREASURE_HUNTER
c2gtcnNhAAAAAwEAAQAAAYEA0FAKE1234567890TEST0FAKE1234567890TEST
-----END OPENSSH PRIVATE KEY-----
"@ | Set-Content "$ssh_dir\id_rsa" -Encoding UTF8

@"
ssh-rsa AAAAB3NzaC1yc2EAAAATEST_PUBLIC_KEY_FAKE test@treasure-target
"@ | Set-Content "$ssh_dir\id_rsa.pub" -Encoding UTF8

@"
Host prod-db
    HostName 10.0.1.50
    User admin
    IdentityFile ~/.ssh/id_rsa

Host staging-web
    HostName 10.0.2.100
    User deploy
"@ | Set-Content "$ssh_dir\config" -Encoding UTF8

# ---------------------------------------------------------------
# 7. .env Files
# ---------------------------------------------------------------
Write-Host "[7/16] Environment files..." -ForegroundColor Yellow
@"
# Production secrets - DO NOT COMMIT (this is a test file)
DATABASE_URL=postgresql://admin:FakeDbPassword123@db.corp.test:5432/production
REDIS_URL=redis://:FakeRedisPass@cache.corp.test:6379
API_SECRET_KEY=sk_live_FAKE1234567890abcdefghijklmnop
STRIPE_SECRET=sk_test_FAKEstripeKeyForTesting12345
JWT_SECRET=FakeJwtSecret+ForTreasureHunterTesting/2024
"@ | Set-Content "$home_dir\Desktop\.env" -Encoding UTF8

@"
DB_PASSWORD=FakeStagingDbPass
API_KEY=staging-api-key-fake-12345
"@ | Set-Content "$home_dir\Documents\.env.staging" -Encoding UTF8

# ---------------------------------------------------------------
# 8. npm / pip / Gradle Credentials
# ---------------------------------------------------------------
Write-Host "[8/16] Package manager credentials..." -ForegroundColor Yellow
@"
//registry.npmjs.org/:_authToken=npm_FAKEtokenForTesting1234567890
//npm.pkg.github.com/:_authToken=ghp_FakeGitHubPackagesToken123
"@ | Set-Content "$home_dir\.npmrc" -Encoding UTF8

@"
[distutils]
index-servers = pypi

[pypi]
repository = https://upload.pypi.org/legacy/
username = __token__
password = pypi-FakeTokenForTestingTreasureHunter1234
"@ | Set-Content "$home_dir\.pypirc" -Encoding UTF8

$gradle_dir = "$home_dir\.gradle"
New-Item -ItemType Directory -Path $gradle_dir -Force | Out-Null
@"
nexusUsername=deployer
nexusPassword=FakeNexusPassword123!
sonatypeToken=FAKE_SONATYPE_TOKEN_1234567890
"@ | Set-Content "$gradle_dir\gradle.properties" -Encoding UTF8

# ---------------------------------------------------------------
# 9. PowerShell History (type commands with fake passwords)
# ---------------------------------------------------------------
Write-Host "[9/16] PowerShell history..." -ForegroundColor Yellow
$ps_history_dir = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline"
New-Item -ItemType Directory -Path $ps_history_dir -Force | Out-Null

@"
Get-Process
cd C:\Projects
git pull origin main
Invoke-SqlCmd -ServerInstance db.corp.test -Database prod -Username sa -Password FakeSqlPassword123!
docker login registry.corp.test -u admin -p FakeDockerRegistryPass
ssh admin@10.0.0.50
export AWS_SECRET_ACCESS_KEY=FakeExportedAwsKey12345
net use \\fileserver\shared /user:CORP\svc_backup FakeNetUsePassword!
kubectl --token=eyJhbGciOiJSUzI1NiFAKE get pods -n production
"@ | Set-Content "$ps_history_dir\ConsoleHost_history.txt" -Encoding UTF8

# ---------------------------------------------------------------
# 10. Sticky Notes
# ---------------------------------------------------------------
Write-Host "[10/16] Sticky Notes..." -ForegroundColor Yellow
$notes_dir = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState"
if (-not (Test-Path $notes_dir)) {
    New-Item -ItemType Directory -Path $notes_dir -Force | Out-Null
}
# Create a minimal SQLite with a note containing a "password"
$db_path = "$notes_dir\plum.sqlite"
# Use Python if available, otherwise create a placeholder
if (Get-Command python -ErrorAction SilentlyContinue) {
    python -c @"
import sqlite3
conn = sqlite3.connect(r'$db_path')
conn.execute('CREATE TABLE IF NOT EXISTS Note (Text TEXT, Id TEXT)')
conn.execute("INSERT INTO Note VALUES ('Server admin password: FakeStickyNotePass123!', '1')")
conn.execute("INSERT INTO Note VALUES ('VPN token: vpn-fake-token-9876543210', '2')")
conn.commit()
conn.close()
"@
} else {
    "Server admin password: FakeStickyNotePass123!" | Set-Content "$notes_dir\notes.txt"
}

# ---------------------------------------------------------------
# 11. Docker Config
# ---------------------------------------------------------------
Write-Host "[11/16] Docker config..." -ForegroundColor Yellow
$docker_dir = "$home_dir\.docker"
New-Item -ItemType Directory -Path $docker_dir -Force | Out-Null

$docker_auth = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("admin:FakeDockerHubToken123"))
@"
{
    "auths": {
        "https://index.docker.io/v1/": {
            "auth": "$docker_auth"
        },
        "registry.corp.test": {
            "auth": "$( [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("deploy:FakeCorpRegistryPass")))"
        }
    }
}
"@ | Set-Content "$docker_dir\config.json" -Encoding UTF8

# ---------------------------------------------------------------
# 12. Kubernetes Config
# ---------------------------------------------------------------
Write-Host "[12/16] Kubernetes config..." -ForegroundColor Yellow
$kube_dir = "$home_dir\.kube"
New-Item -ItemType Directory -Path $kube_dir -Force | Out-Null

@"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.corp.test:6443
    certificate-authority-data: LS0tFAKECERTDATA
  name: prod-cluster
contexts:
- context:
    cluster: prod-cluster
    user: admin
  name: prod
current-context: prod
users:
- name: admin
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0UifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwic3ViIjoiYWRtaW4ifQ.FAKE_SIGNATURE
"@ | Set-Content "$kube_dir\config" -Encoding UTF8

# ---------------------------------------------------------------
# 13. RDP Connection History
# ---------------------------------------------------------------
Write-Host "[13/16] RDP history..." -ForegroundColor Yellow
$rdp_base = "HKCU:\Software\Microsoft\Terminal Server Client\Servers"
New-Item -Path $rdp_base -Force | Out-Null

@("10.0.1.10", "dc01.corp.test", "fileserver.corp.test") | ForEach-Object {
    $server_path = "$rdp_base\$_"
    New-Item -Path $server_path -Force | Out-Null
    Set-ItemProperty -Path $server_path -Name "UsernameHint" -Value "CORP\admin"
}

# Create an .rdp file
@"
full address:s:10.0.1.10
username:s:CORP\admin
server port:i:3389
prompt for credentials:i:0
"@ | Set-Content "$home_dir\Desktop\prod-server.rdp" -Encoding UTF8

# ---------------------------------------------------------------
# 14. KeePass Database
# ---------------------------------------------------------------
Write-Host "[14/16] KeePass database placeholder..." -ForegroundColor Yellow
# Create a file with KeePass magic bytes
$keepass_magic = [byte[]]@(0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5)
$keepass_path = "$home_dir\Documents\passwords.kdbx"
[IO.File]::WriteAllBytes($keepass_path, $keepass_magic + (New-Object byte[] 1024))

# ---------------------------------------------------------------
# 15. SMB Shares (for network scanning test)
# ---------------------------------------------------------------
Write-Host "[15/16] SMB shares..." -ForegroundColor Yellow
$share_dir = "C:\Shared"
New-Item -ItemType Directory -Path "$share_dir\Finance" -Force | Out-Null
New-Item -ItemType Directory -Path "$share_dir\IT" -Force | Out-Null

"Q3 2024 Revenue: $12.3M (FAKE DATA)" | Set-Content "$share_dir\Finance\quarterly-report.xlsx"
"admin:FakePassword123" | Set-Content "$share_dir\IT\server-credentials.txt"

try {
    New-SmbShare -Name "Finance" -Path "$share_dir\Finance" -FullAccess "Everyone" -ErrorAction Stop
    New-SmbShare -Name "IT" -Path "$share_dir\IT" -FullAccess "Everyone" -ErrorAction Stop
} catch {
    Write-Host "  SMB share creation requires elevated rights or server OS" -ForegroundColor DarkYellow
}

# ---------------------------------------------------------------
# 16. GitHub CLI Token
# ---------------------------------------------------------------
Write-Host "[16/16] GitHub CLI + Vault token..." -ForegroundColor Yellow
$gh_dir = "$home_dir\.config\gh"
New-Item -ItemType Directory -Path $gh_dir -Force | Out-Null
@"
github.com:
    oauth_token: ghp_FAKEgithubCliToken1234567890abcdef
    user: testoperator
    git_protocol: https
"@ | Set-Content "$gh_dir\hosts.yml" -Encoding UTF8

# Vault token
"hvs.FAKEvaultTokenForTesting1234567890abcdef" | Set-Content "$home_dir\.vault-token" -Encoding UTF8

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
Write-Host "`n=== Seeding Complete ===" -ForegroundColor Green
Write-Host "Planted artifacts for all 16 grabber modules:"
Write-Host "  [+] AWS credentials (.aws/credentials)"
Write-Host "  [+] Git credentials (.git-credentials + repo config)"
Write-Host "  [+] FileZilla (3 saved servers with base64 passwords)"
Write-Host "  [+] PuTTY (3 registry sessions)"
Write-Host "  [+] Windows AutoLogon (registry)"
Write-Host "  [+] SSH keys (.ssh/id_rsa + config)"
Write-Host "  [+] .env files (Desktop + Documents)"
Write-Host "  [+] npm/pip/Gradle tokens"
Write-Host "  [+] PowerShell history (typed passwords)"
Write-Host "  [+] Sticky Notes (plum.sqlite)"
Write-Host "  [+] Docker config (registry auth)"
Write-Host "  [+] Kubernetes config (cluster token)"
Write-Host "  [+] RDP history (registry + .rdp file)"
Write-Host "  [+] KeePass database placeholder"
Write-Host "  [+] SMB shares (Finance + IT)"
Write-Host "  [+] GitHub CLI + Vault tokens"
Write-Host "`nReady for treasure-hunter scan!" -ForegroundColor Cyan
