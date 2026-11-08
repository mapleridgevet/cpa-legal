# Explicit local migration. Does not start the listener and does not call Intuit.
# Hashes a reversible owner password, keeps the session secret and Intuit keys,
# and can encrypt a plaintext token file. Prints no password, hash, key, or token.
# With no -DataDir, the live data folder is used. Tests must pass -DataDir and set
# CPA_MIGRATION_ISOLATED=1, which rejects that live folder.
param(
  [string]$DataDir = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth",
  [switch]$ResolveOnly
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

function Assert-MigrationPath {
  param([string]$Candidate)
  $full = [System.IO.Path]::GetFullPath($Candidate)
  if ($env:CPA_MIGRATION_ISOLATED -ne "1") { return $full }
  $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd("\")
  $probe = $full.TrimEnd("\")
  if (-not ($probe.Equals($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or $probe.StartsWith($tempRoot + "\", [StringComparison]::OrdinalIgnoreCase))) {
    throw "Refusing isolated migration outside TEMP."
  }
  foreach ($blocked in @(
    "C:\Users\naesm\cpa-oauth-service",
    "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth",
    "C:\Users\naesm\quickbooks-card-connector"
  )) {
    $blockFull = [System.IO.Path]::GetFullPath($blocked).TrimEnd("\")
    if ($probe.Equals($blockFull, [StringComparison]::OrdinalIgnoreCase) -or $probe.StartsWith($blockFull + "\", [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing isolated migration on a live CPA path."
    }
  }
  return $full
}

$DataDir = Assert-MigrationPath $DataDir
if ($ResolveOnly) {
  if ($env:CPA_MIGRATION_ISOLATED -ne "1") { throw "ResolveOnly is only available for an isolated test." }
  Write-Output $DataDir
  exit 0
}
Write-Output "MIGRATION_STARTED"
$SecretPath = Join-Path $DataDir "secrets.clixml"
$TokenPath = Join-Path $DataDir "qbo-tokens.json"

function Convert-FromSecure {
  param([Security.SecureString]$Value)
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Protect-OwnerOnly {
  param([string]$Target)
  & node (Join-Path $Here "src\protect-path.js") $Target
  if ($LASTEXITCODE -ne 0) { throw "Could not restrict the DACL. Nothing was replaced." }
}

function Save-SecretBag {
  param($Bag)
  $dest = $SecretPath
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
    return $backup
  } catch {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    if ($movedAside -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $dest)) {
      Move-Item -LiteralPath $backup -Destination $dest -Force
    }
    throw
  }
}

Write-Host "Migration scope: hash the owner password if it is still reversible; keep the session secret and any Intuit keys; create a separate token key if missing; encrypt qbo-tokens.json if it is plaintext."
Write-Host "This does not start the listener, does not call Intuit, and does not display secrets."

if (-not (Test-Path -LiteralPath $SecretPath)) {
  Write-Host "No secrets file was found. Nothing was changed."
  exit 1
}

$secrets = Import-Clixml -LiteralPath $SecretPath
$session = $secrets.SESSION_SECRET
if ($session -isnot [System.Security.SecureString] -or $session.Length -lt 32) {
  Write-Host "Session secret is missing. Nothing was changed."
  exit 1
}

$reversible = $secrets.OWNER_PASSWORD
$existingHash = $secrets.OWNER_PASSWORD_HASH
$hasReversible = ($reversible -is [System.Security.SecureString]) -and $reversible.Length -ge 16
$hasHash = ($existingHash -is [string]) -and $existingHash.StartsWith("scrypt$")
if ($hasReversible -and $hasHash) {
  Write-Host "Both a reversible owner password and a hash are present. Nothing was changed."
  exit 1
}
if (-not $hasReversible -and -not $hasHash) {
  Write-Host "Owner sign-in is not configured. Nothing was changed."
  exit 1
}

$ownerPlain = ""
$ownerHash = ""
if ($hasHash) {
  $ownerHash = [string]$existingHash
  Write-Host "Owner password is already one-way. It was left in place."
} else {
  $ownerPlain = Convert-FromSecure $reversible
  $env:OWNER_PASSWORD = $ownerPlain
  try {
    $ownerHash = [string](& node (Join-Path $Here "src\owner-password-cli.js") hash)
    if ($LASTEXITCODE -ne 0 -or -not $ownerHash.StartsWith("scrypt$")) { throw "Owner password hash failed. Nothing was changed." }
    $env:OWNER_PASSWORD_HASH = $ownerHash
    $verify = [string](& node (Join-Path $Here "src\owner-password-cli.js") verify)
    if ($LASTEXITCODE -ne 0 -or $verify.Trim() -ne "match") { throw "Owner password hash did not verify. Nothing was changed." }
  } catch {
    Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
    $ownerPlain = $null
    Write-Host "Owner password migration failed. The secret file was not replaced."
    exit 1
  } finally {
    Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
  }
}

$tokenKey = $secrets.TOKEN_ENC_KEY
$createdKey = $false
if (-not (($tokenKey -is [System.Security.SecureString]) -and $tokenKey.Length -gt 0)) {
  $keyText = [string](& node (Join-Path $Here "src\token-key-cli.js"))
  if ($LASTEXITCODE -ne 0 -or $keyText.Length -lt 40) {
    Write-Host "Token key creation failed. The secret file was not replaced."
    exit 1
  }
  $tokenKey = ConvertTo-SecureString $keyText -AsPlainText -Force
  $keyText = $null
  $createdKey = $true
}

$bag = [ordered]@{
  OWNER_PASSWORD_HASH = $ownerHash
  SESSION_SECRET = $session
  TOKEN_ENC_KEY = $tokenKey
}
if (($secrets.QBO_CLIENT_ID -is [System.Security.SecureString]) -and $secrets.QBO_CLIENT_ID.Length -gt 0) {
  $bag.QBO_CLIENT_ID = $secrets.QBO_CLIENT_ID
}
if (($secrets.QBO_CLIENT_SECRET -is [System.Security.SecureString]) -and $secrets.QBO_CLIENT_SECRET.Length -gt 0) {
  $bag.QBO_CLIENT_SECRET = $secrets.QBO_CLIENT_SECRET
}

$backup = ""
try {
  $backup = Save-SecretBag $bag
  $written = Import-Clixml -LiteralPath $SecretPath
  $writtenHash = [string]$written.OWNER_PASSWORD_HASH
  if (-not $writtenHash.StartsWith("scrypt$")) { throw "Saved hash was not readable." }
  if ($hasReversible) {
    $env:OWNER_PASSWORD = $ownerPlain
    $env:OWNER_PASSWORD_HASH = $writtenHash
    $verify = [string](& node (Join-Path $Here "src\owner-password-cli.js") verify)
    if ($LASTEXITCODE -ne 0 -or $verify.Trim() -ne "match") { throw "Saved hash did not verify." }
  }
  if ($written.OWNER_PASSWORD -is [System.Security.SecureString]) { throw "Reversible owner password is still present." }
  if ($backup -and (Test-Path -LiteralPath $backup)) { Remove-Item -LiteralPath $backup -Force }
  $backup = ""
} catch {
  if ($backup -and (Test-Path -LiteralPath $backup)) {
    Move-Item -LiteralPath $backup -Destination $SecretPath -Force
    Write-Host "Owner secret migration failed and the previous secret file was restored."
  } else {
    Write-Host "Owner secret migration failed. The previous secret file was left in place if it still exists."
  }
  Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
  Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
  $ownerPlain = $null
  exit 1
}
Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
$ownerPlain = $null

if ($hasReversible) { Write-Host "Owner password was replaced with a one-way hash. The reversible value was removed." }
if ($createdKey) { Write-Host "A separate token encryption key was saved. It is not in the token file." }
else { Write-Host "The existing token encryption key was kept." }

if (-not (Test-Path -LiteralPath $TokenPath)) {
  Write-Host "No token file was present. No tokens were deleted."
  Write-Host "The listener was not started."
  exit 0
}

$keyPlain = Convert-FromSecure $tokenKey
$env:TOKEN_ENC_KEY = $keyPlain
try {
  $tokenResult = [string](& node (Join-Path $Here "src\migrate-token-file.js") $TokenPath)
  if ($LASTEXITCODE -ne 0) { throw "Token migration failed." }
  Write-Host ("Token file status: " + $tokenResult.Trim() + ". No plaintext backup was kept.")
} catch {
  Write-Host "Token migration failed. The original token file was not deleted."
  exit 1
} finally {
  Remove-Item Env:TOKEN_ENC_KEY -ErrorAction SilentlyContinue
  $keyPlain = $null
}
Write-Host "The listener was not started."
exit 0
