# Places the OAuth program and checks it. Does not start it and does not call Intuit or Cloudflare.
# Secrets are accepted only with -ConfigureSecrets, as masked prompts, never as arguments.
param(
  [switch]$ConfigureSecrets
)

$ErrorActionPreference = "Stop"
$ProgramDir = "C:\Users\naesm\cpa-oauth-service"
$DataDir = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth"
$ConnectorDir = "C:\Users\naesm\quickbooks-card-connector"
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Assert-NotConnector {
  param([string]$Candidate)
  $full = [System.IO.Path]::GetFullPath($Candidate)
  $blocked = [System.IO.Path]::GetFullPath($ConnectorDir)
  if ($full.Equals($blocked, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($blocked + "\", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to touch the QuickBooks connector directory."
  }
}

function Protect-OwnerOnly {
  param([string]$Target)
  $user = $env:USERNAME
  $item = Get-Item -LiteralPath $Target
  if ($item.PSIsContainer) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $user,
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
      [System.Security.AccessControl.PropagationFlags]::None,
      [System.Security.AccessControl.AccessControlType]::Allow
    )
  } else {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $user,
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      [System.Security.AccessControl.AccessControlType]::Allow
    )
  }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $Target -AclObject $acl
  $check = Get-Acl -LiteralPath $Target
  if (-not $check.AreAccessRulesProtected -or @($check.Access).Count -ne 1) {
    throw "ACL on $Target is not limited to $user. Nothing was started."
  }
}

function Read-MaskedSecret {
  param([string]$Label, [int]$Minimum)
  $secret = Read-Host -AsSecureString -Prompt $Label
  if ($null -eq $secret -or $secret.Length -lt $Minimum) {
    throw "That value is too short. Nothing was saved and the service was not started."
  }
  return $secret
}

Assert-NotConnector $ProgramDir
Assert-NotConnector $DataDir

if (-not $SourceDir.Equals([System.IO.Path]::GetFullPath($ProgramDir), [StringComparison]::OrdinalIgnoreCase)) {
  New-Item -ItemType Directory -Force -Path $ProgramDir | Out-Null
  $names = @(
    "package.json",
    "package-lock.json",
    "host-settings.json",
    "src",
    "test",
    "install.ps1",
    "start-oauth-service.ps1",
    "README.md"
  )
  foreach ($name in $names) {
    $from = Join-Path $SourceDir $name
    if (-not (Test-Path -LiteralPath $from)) {
      throw "Release is missing $name"
    }
    Copy-Item -LiteralPath $from -Destination (Join-Path $ProgramDir $name) -Recurse -Force
  }
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Protect-OwnerOnly $DataDir

$hostSettings = Get-Content -LiteralPath (Join-Path $ProgramDir "host-settings.json") -Raw | ConvertFrom-Json
if ($hostSettings.publicBaseUrl -ne "https://mapleridgecpa.com") { throw "Unexpected public URL." }
if ($hostSettings.redirectUri -ne "https://mapleridgecpa.com/callback") { throw "Unexpected callback URL." }
if ($hostSettings.bindHost -ne "127.0.0.1" -or [int]$hostSettings.port -ne 8787) { throw "Unexpected bind address." }

$publicConfig = [ordered]@{
  PUBLIC_BASE_URL = $hostSettings.publicBaseUrl
  QBO_REDIRECT_URI = $hostSettings.redirectUri
  QBO_ENVIRONMENT = "production"
  BIND_HOST = $hostSettings.bindHost
  PORT = [string]$hostSettings.port
  COOKIE_SECURE = "true"
  DATA_DIR = $DataDir
  QBO_SCOPE = "com.intuit.quickbooks.accounting"
}
$configPath = Join-Path $DataDir "service-config.json"
foreach ($kept in @("secrets.clixml", "qbo-tokens.json", "oauth-state.json")) {
  if (Test-Path -LiteralPath (Join-Path $DataDir $kept)) {
    Write-Host "Left existing $kept in place."
  }
}
if (Test-Path -LiteralPath $configPath) {
  Write-Host "Left existing service-config.json in place."
} else {
  $publicConfig | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding utf8
  Protect-OwnerOnly $configPath
}

if ($ConfigureSecrets) {
  $bag = [ordered]@{
    QBO_CLIENT_ID = Read-MaskedSecret "Intuit production client id (input stays hidden)" 8
    QBO_CLIENT_SECRET = Read-MaskedSecret "Intuit production client secret (input stays hidden)" 8
    OWNER_PASSWORD = Read-MaskedSecret "Owner password, 16 or more characters (input stays hidden)" 16
    SESSION_SECRET = Read-MaskedSecret "Session secret, 32 or more characters (input stays hidden)" 32
  }
  $secretPath = Join-Path $DataDir "secrets.clixml"
  $bag | Export-Clixml -LiteralPath $secretPath
  Protect-OwnerOnly $secretPath
  Write-Host "Secrets were saved for this Windows user only. They were not displayed."
  Write-Host "The service was not started. OAuth was not attempted."
  exit 0
}

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
  throw "Node.js 20 or newer was not found. The service was not started."
}
$versionText = & node -v
if ($versionText -notmatch "^v(\d+)\.") {
  throw "Could not read the Node.js version. The service was not started."
}
if ([int]$Matches[1] -lt 20) {
  throw "Node.js 20 or newer is required. The service was not started."
}

Push-Location $ProgramDir
try {
  & node --test
  if ($LASTEXITCODE -ne 0) {
    throw "Tests failed. The service was not started."
  }
  & node src/preflight.js
  if ($LASTEXITCODE -ne 0) {
    throw "Health check failed. The service was not started."
  }
} finally {
  Pop-Location
}

Write-Host "Program directory: $ProgramDir"
Write-Host "Data directory: $DataDir"
Write-Host "OAuth was not attempted. No listener was started. No Intuit credentials are stored."
Write-Host "Cloudflare was not changed. The tunnel route still has to be hostname mapleridgecpa.com to http://127.0.0.1:8787."
exit 0
