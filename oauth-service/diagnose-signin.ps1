# Reads the saved sign-in file and reports only lengths and character classes.
# It does not print the password, the session secret, or any hash.
# It does not change secrets, config, tokens, or the throttle file.
# It does not listen and does not start the service unless -Listen is passed.
param(
  [string]$DataDir = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth",
  [switch]$Listen
)

$ErrorActionPreference = "Stop"
$SecretPath = Join-Path $DataDir "secrets.clixml"

function Write-Diag {
  param([string]$Name, [string]$Value)
  if ($Value -match "[\r\n]") { $Value = "rejected" }
  Write-Host ("DIAG|" + $Name + "|" + $Value)
}

function Convert-FlagValue {
  param($Value)
  if ($Value -is [bool]) {
    if ($Value) { return "true" }
    return "false"
  }
  return [string]$Value
}

function Get-SecretFlags {
  param([string]$Value)
  $flags = @{
    Length = $Value.Length
    NonAscii = $false
    Replacement = $false
    Cr = $false
    Lf = $false
    Tab = $false
    Space = $false
    Nul = $false
    LeadingSpace = $Value.StartsWith(" ")
    TrailingSpace = $Value.EndsWith(" ")
  }
  foreach ($ch in $Value.ToCharArray()) {
    $code = [int]$ch
    if ($code -gt 127) { $flags["NonAscii"] = $true }
    if ($code -eq 65533) { $flags["Replacement"] = $true }
    if ($code -eq 13) { $flags["Cr"] = $true }
    if ($code -eq 10) { $flags["Lf"] = $true }
    if ($code -eq 9) { $flags["Tab"] = $true }
    if ($code -eq 32) { $flags["Space"] = $true }
    if ($code -eq 0) { $flags["Nul"] = $true }
  }
  return $flags
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

if (-not (Test-Path -LiteralPath $SecretPath)) {
  Write-Diag "secretFile" "missing"
  exit 1
}

try {
  $secrets = Import-Clixml -LiteralPath $SecretPath
} catch {
  Write-Diag "secretFile" "unreadable"
  exit 1
}

$ownerSecure = $secrets.OWNER_PASSWORD
$sessionSecure = $secrets.SESSION_SECRET
if ($ownerSecure -isnot [System.Security.SecureString]) {
  Write-Diag "ownerType" "unexpected"
  exit 1
}
if ($sessionSecure -isnot [System.Security.SecureString]) {
  Write-Diag "sessionType" "unexpected"
  exit 1
}
Write-Diag "ownerType" "SecureString"
Write-Diag "sessionType" "SecureString"

$ownerPlain = Convert-FromSecure $ownerSecure
$sessionPlain = Convert-FromSecure $sessionSecure
$ownerParent = Get-SecretFlags $ownerPlain
$sessionParent = Get-SecretFlags $sessionPlain

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$js = Join-Path $here "src\secret-diagnostic.js"
if (-not (Test-Path -LiteralPath $js)) {
  $js = Join-Path $here "secret-diagnostic.js"
}
if (-not (Test-Path -LiteralPath $js)) {
  Write-Diag "diagnostic" "missing-script"
  exit 1
}

$names = @("OWNER_PASSWORD", "SESSION_SECRET", "CPA_DIAG_MODE", "CPA_DIAG_PORT")
try {
  Set-Item -Path Env:OWNER_PASSWORD -Value $ownerPlain
  Set-Item -Path Env:SESSION_SECRET -Value $sessionPlain
  if ($Listen) {
    Set-Item -Path Env:CPA_DIAG_MODE -Value "listen"
    Set-Item -Path Env:CPA_DIAG_PORT -Value "8787"
    Write-Diag "listened" "starting"
  } else {
    Remove-Item Env:CPA_DIAG_MODE -ErrorAction SilentlyContinue
    Write-Diag "listened" "false"
  }
  $child = & node $js
  if ($LASTEXITCODE -ne 0 -and -not $Listen) {
    Write-Diag "child" "failed"
  }
  $childMap = @{}
  foreach ($line in @($child)) {
    if ($line -match "^DIAG\|([^|]+)\|([^|]*)$") {
      $childMap[$Matches[1]] = $Matches[2]
      Write-Host $line
    }
  }
  $same = $true
  foreach ($pair in @(
    @{ Parent = "ownerParent"; Child = "ownerChild"; Flags = $ownerParent },
    @{ Parent = "sessionParent"; Child = "sessionChild"; Flags = $sessionParent }
  )) {
    foreach ($key in $pair.Flags.Keys) {
      $parentValue = Convert-FlagValue $pair.Flags[$key]
      $childValue = [string]$childMap[$pair.Child + $key]
      Write-Diag ($pair.Parent + $key) $parentValue
      if ($childValue -ne $parentValue) { $same = $false }
    }
  }
  if ($same) { Write-Diag "handoffSame" "true" } else { Write-Diag "handoffSame" "false" }
  Write-Diag "filesChanged" "false"
} catch {
  Write-Diag "diagnostic" "failed"
  exit 1
} finally {
  foreach ($name in $names) {
    Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
  }
  $ownerPlain = $null
  $sessionPlain = $null
}
