# Starts the local listener only when a DPAPI secret file already exists.
# Do not pass secrets on the command line. This script does not print them.
$ErrorActionPreference = "Stop"
$ProgramDir = "C:\Users\naesm\cpa-oauth-service"
$DataDir = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth"
$SecretPath = Join-Path $DataDir "secrets.clixml"
$ConfigPath = Join-Path $DataDir "service-config.json"

if (-not (Test-Path -LiteralPath $SecretPath) -or -not (Test-Path -LiteralPath $ConfigPath)) {
  Write-Host "Not started. Owner sign-in is not configured. OAuth was not attempted."
  exit 1
}

$cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($cfg.BIND_HOST -ne "127.0.0.1" -or $cfg.PORT -ne "8787") {
  Write-Host "Not started. Bind address is not 127.0.0.1:8787."
  exit 1
}
if ($cfg.PUBLIC_BASE_URL -ne "https://mapleridgecpa.com" -or $cfg.QBO_REDIRECT_URI -ne "https://mapleridgecpa.com/callback") {
  Write-Host "Not started. Public URL or callback does not match https://mapleridgecpa.com/callback."
  exit 1
}

$secrets = Import-Clixml -LiteralPath $SecretPath

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

$hasReversibleOwner = Test-SecurePresent $secrets "OWNER_PASSWORD" 1
$hasOwnerHash = ($secrets.OWNER_PASSWORD_HASH -is [string]) -and $secrets.OWNER_PASSWORD_HASH.StartsWith("scrypt$")
if ($hasReversibleOwner -and -not $hasOwnerHash) {
  Write-Host "Not started. The owner password is still reversible. Run migrate-secrets.ps1. Nothing was started."
  exit 1
}
if ($hasReversibleOwner -and $hasOwnerHash) {
  Write-Host "Not started. Both a reversible owner password and a hash are present. Nothing was started."
  exit 1
}
if (-not $hasOwnerHash -or -not (Test-SecurePresent $secrets "SESSION_SECRET" 32)) {
  Write-Host "Not started. Owner sign-in is not configured. OAuth was not attempted."
  exit 1
}
$hasClientId = Test-SecurePresent $secrets "QBO_CLIENT_ID" 1
$hasClientSecret = Test-SecurePresent $secrets "QBO_CLIENT_SECRET" 1
if ($hasClientId -xor $hasClientSecret) {
  Write-Host "Not started. Intuit credentials are partial. OAuth was not attempted."
  exit 1
}

$names = @("OWNER_PASSWORD_HASH", "SESSION_SECRET")
if (Test-SecurePresent $secrets "TOKEN_ENC_KEY" 1) { $names += @("TOKEN_ENC_KEY") }
if ($hasClientId -and $hasClientSecret) {
  $names += @("QBO_CLIENT_ID", "QBO_CLIENT_SECRET")
  Write-Host "Starting with QuickBooks credentials configured. Tokens are not displayed."
} else {
  Remove-Item Env:QBO_CLIENT_ID -ErrorAction SilentlyContinue
  Remove-Item Env:QBO_CLIENT_SECRET -ErrorAction SilentlyContinue
  Write-Host "Starting in setup mode. OAuth is not configured."
}
Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue

try {
  foreach ($name in $names) {
    if ($name -eq "OWNER_PASSWORD_HASH") {
      Set-Item -Path "Env:$name" -Value ([string]$secrets.OWNER_PASSWORD_HASH)
    } else {
      Set-Item -Path "Env:$name" -Value (Convert-FromSecure $secrets.$name)
    }
  }
  $env:QBO_REDIRECT_URI = [string]$cfg.QBO_REDIRECT_URI
  $env:QBO_ENVIRONMENT = [string]$cfg.QBO_ENVIRONMENT
  $env:PUBLIC_BASE_URL = [string]$cfg.PUBLIC_BASE_URL
  $env:DATA_DIR = [string]$cfg.DATA_DIR
  $env:BIND_HOST = [string]$cfg.BIND_HOST
  $env:PORT = [string]$cfg.PORT
  $env:COOKIE_SECURE = [string]$cfg.COOKIE_SECURE
  $env:QBO_SCOPE = [string]$cfg.QBO_SCOPE
  Set-Location $ProgramDir
  & node src/index.js
  exit $LASTEXITCODE
} finally {
  foreach ($name in @("OWNER_PASSWORD", "OWNER_PASSWORD_HASH", "SESSION_SECRET", "QBO_CLIENT_ID", "QBO_CLIENT_SECRET", "TOKEN_ENC_KEY")) {
    Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
  }
}
