# Starts the local listener only when a DPAPI secret file already exists.
# Do not pass secrets on the command line. This script does not print them.
$ErrorActionPreference = "Stop"
$ProgramDir = "C:\Users\naesm\cpa-oauth-service"
$DataDir = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth"
$SecretPath = Join-Path $DataDir "secrets.clixml"
$ConfigPath = Join-Path $DataDir "service-config.json"

if (-not (Test-Path -LiteralPath $SecretPath) -or -not (Test-Path -LiteralPath $ConfigPath)) {
  Write-Host "Not started. Credentials are not configured. OAuth was not attempted."
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

$names = @("QBO_CLIENT_ID", "QBO_CLIENT_SECRET", "OWNER_PASSWORD", "SESSION_SECRET")
try {
  foreach ($name in $names) {
    Set-Item -Path "Env:$name" -Value (Convert-FromSecure $secrets.$name)
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
  foreach ($name in $names) {
    Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
  }
}
