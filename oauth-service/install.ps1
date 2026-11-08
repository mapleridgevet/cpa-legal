# Places the OAuth program and checks it. Does not start it and does not call Intuit or Cloudflare.
# -ConfigureOwner saves the owner password and session secret only.
# -ConfigureIntuit adds both production keys later and keeps the owner secrets.
# Prompts are masked. Secrets are never arguments.
param(
  [switch]$ConfigureOwner,
  [switch]$ConfigureIntuit
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
  & node (Join-Path $ProgramDir "src\protect-path.js") $Target
  if ($LASTEXITCODE -ne 0) {
    throw "Could not restrict the DACL. Nothing was started."
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

function Convert-FromSecure {
  param([Security.SecureString]$Value)
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
  }
}

function Test-SecurePresent {
  param($Bag, [string]$Name, [int]$Minimum)
  if ($null -eq $Bag) { return $false }
  $value = $Bag.$Name
  return ($null -ne $value -and $value -is [System.Security.SecureString] -and $value.Length -ge $Minimum)
}

function Get-IntuitPresence {
  param($Bag)
  return @{
    Id = (Test-SecurePresent $Bag "QBO_CLIENT_ID" 1)
    Secret = (Test-SecurePresent $Bag "QBO_CLIENT_SECRET" 1)
  }
}

function Save-SecretBag {
  param($Bag)
  $dest = Join-Path $DataDir "secrets.clixml"
  $temp = Join-Path $DataDir ("secrets-" + [guid]::NewGuid().ToString("n") + ".tmp")
  $backup = Join-Path $DataDir ("secrets-" + [guid]::NewGuid().ToString("n") + ".bak")
  $Bag | Export-Clixml -LiteralPath $temp
  Protect-OwnerOnly $temp
  $movedAside = $false
  try {
    if (Test-Path -LiteralPath $dest) {
      Move-Item -LiteralPath $dest -Destination $backup -Force
      $movedAside = $true
    }
    Move-Item -LiteralPath $temp -Destination $dest -Force
    Protect-OwnerOnly $dest
    if ($movedAside -and (Test-Path -LiteralPath $backup)) {
      Remove-Item -LiteralPath $backup -Force
    }
  } catch {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    if ($movedAside -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $dest)) {
      Move-Item -LiteralPath $backup -Destination $dest -Force
    }
    throw
  }
}

Assert-NotConnector $ProgramDir
Assert-NotConnector $DataDir

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

& node (Join-Path $SourceDir "src\install-files.js") $SourceDir $ProgramDir
if ($LASTEXITCODE -ne 0) {
  throw "Install copy failed. Nothing was started."
}
$helper = Join-Path $ProgramDir "src\protect-path.js"
if (-not (Test-Path -LiteralPath $helper)) {
  throw "Install copy did not place $helper. Nothing was started."
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
foreach ($kept in @("secrets.clixml", "qbo-tokens.json", "oauth-state.json", "login-throttle.json")) {
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

if ($ConfigureOwner -and $ConfigureIntuit) {
  throw "Choose one configuration step. Nothing was saved and the service was not started."
}

$existing = $null
$presence = @{ Id = $false; Secret = $false }
if ($ConfigureOwner -or $ConfigureIntuit) {
  $secretPath = Join-Path $DataDir "secrets.clixml"
  if (Test-Path -LiteralPath $secretPath) {
    $existing = Import-Clixml -LiteralPath $secretPath
  }
  $presence = Get-IntuitPresence $existing
}

if ($ConfigureOwner) {
  if ($presence.Id -xor $presence.Secret) {
    throw "Intuit credentials are partial. Nothing was saved and the service was not started."
  }
  $ownerPassword = Read-MaskedSecret "Owner password, 16 or more characters (input stays hidden)" 16
  $sessionSecret = Read-MaskedSecret "Session secret, 32 or more characters (input stays hidden)" 32
  $ownerPlain = Convert-FromSecure $ownerPassword
  $env:OWNER_PASSWORD = $ownerPlain
  $ownerHash = ""
  try {
    $ownerHash = (& node (Join-Path $ProgramDir "src\owner-password-cli.js") hash)
    if ($LASTEXITCODE -ne 0) { throw "Could not hash the owner password. Nothing was saved." }
    $ownerHash = [string]$ownerHash
    if (-not $ownerHash.StartsWith("scrypt$")) { throw "Could not hash the owner password. Nothing was saved." }
    $env:OWNER_PASSWORD_HASH = $ownerHash
    & node (Join-Path $ProgramDir "src\owner-password-cli.js") verify | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Owner password hash did not verify. Nothing was saved." }
  } finally {
    Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
    $ownerPlain = $null
  }
  $bag = [ordered]@{
    OWNER_PASSWORD_HASH = $ownerHash
    SESSION_SECRET = $sessionSecret
  }
  if ($presence.Id -and $presence.Secret) {
    $bag.QBO_CLIENT_ID = $existing.QBO_CLIENT_ID
    $bag.QBO_CLIENT_SECRET = $existing.QBO_CLIENT_SECRET
  }
  if ($null -ne $existing -and ($existing.TOKEN_ENC_KEY -is [System.Security.SecureString]) -and $existing.TOKEN_ENC_KEY.Length -gt 0) {
    $bag.TOKEN_ENC_KEY = $existing.TOKEN_ENC_KEY
  }
  Save-SecretBag $bag
  Write-Host "Owner sign-in secrets were saved for this Windows user only. They were not displayed."
  Write-Host "Intuit keys were not requested. The service was not started. OAuth was not attempted."
  exit 0
}

if ($ConfigureIntuit) {
  if (-not (Test-SecurePresent $existing "OWNER_PASSWORD" 16) -or -not (Test-SecurePresent $existing "SESSION_SECRET" 32)) {
    throw "Owner sign-in is not configured. Nothing was saved and the service was not started."
  }
  $clientId = Read-MaskedSecret "Intuit production client id (input stays hidden)" 8
  $clientSecret = Read-MaskedSecret "Intuit production client secret (input stays hidden)" 8
  $env:QBO_CLIENT_ID = Convert-FromSecure $clientId
  $env:QBO_CLIENT_SECRET = Convert-FromSecure $clientSecret
  $accepted = $false
  try {
    & node (Join-Path $ProgramDir "src\check-intuit-credentials.js")
    if ($LASTEXITCODE -eq 0) { $accepted = $true }
  } finally {
    Remove-Item Env:QBO_CLIENT_ID -ErrorAction SilentlyContinue
    Remove-Item Env:QBO_CLIENT_SECRET -ErrorAction SilentlyContinue
  }
  if (-not $accepted) {
    throw "Intuit credentials were refused. Nothing was saved and the service was not started."
  }
  $intuitBag = [ordered]@{
    SESSION_SECRET = $existing.SESSION_SECRET
    QBO_CLIENT_ID = $clientId
    QBO_CLIENT_SECRET = $clientSecret
  }
  if (($existing.OWNER_PASSWORD_HASH -is [string]) -and $existing.OWNER_PASSWORD_HASH.StartsWith("scrypt$")) {
    $intuitBag.OWNER_PASSWORD_HASH = [string]$existing.OWNER_PASSWORD_HASH
  } elseif (Test-SecurePresent $existing "OWNER_PASSWORD" 16) {
    $intuitBag.OWNER_PASSWORD = $existing.OWNER_PASSWORD
  }
  if (($existing.TOKEN_ENC_KEY -is [System.Security.SecureString]) -and $existing.TOKEN_ENC_KEY.Length -gt 0) {
    $intuitBag.TOKEN_ENC_KEY = $existing.TOKEN_ENC_KEY
  }
  Save-SecretBag $intuitBag
  Write-Host "Intuit production keys were saved. Owner secrets, config, and token files were kept."
  Write-Host "The values were not displayed. The service was not started. OAuth was not attempted."
  exit 0
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
Write-Host "OAuth was not attempted. No listener was started."
Write-Host "Cloudflare was not changed. This script does not publish the sign-in page."
exit 0
