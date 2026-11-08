# Reads the saved sign-in file and reports only lengths and character classes.
# It does not print the password, the session secret, or any hash.
# It does not change secrets, config, tokens, or the throttle file.
# -Compare asks once, locally, for the website password and prints only yes or no.
# It does not listen and does not start the service unless -Listen is passed.
param(
  [string]$DataDir = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth",
  [switch]$Listen,
  [switch]$Compare
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

function Write-ListenerIdentity {
  $found = @()
  try {
    $rows = @(netstat -ano -p tcp)
  } catch {
    Write-Diag "listenerCount" "unknown"
    return
  }
  foreach ($line in $rows) {
    if ($line -match "^\s*TCP\s+\S+:8787\s+\S+\s+LISTENING\s+(\d+)\s*$") {
      $found += $Matches[1]
    }
  }
  $unique = @($found | Select-Object -Unique)
  if ($found.Count -eq 0) {
    Write-Diag "listenerCount" "0"
    return
  }
  Write-Diag "listenerCount" ([string]$unique.Count)
  foreach ($procId in $unique) {
    try {
      $proc = Get-Process -Id ([int]$procId) -ErrorAction Stop
      Write-Diag "listenerName" ([string]$proc.ProcessName)
      Write-Diag "listenerPid" ([string]$proc.Id)
      if ($proc.StartTime) {
        Write-Diag "listenerStarted" ($proc.StartTime.ToString("yyyy-MM-ddTHH:mm:ss"))
      }
      if ($proc.Path) { Write-Diag "listenerPath" ([string]$proc.Path) }
    } catch {
      Write-Diag "listenerName" "unavailable"
    }
  }
}

if ($Listen -and $Compare) {
  Write-Diag "diagnostic" "choose-one"
  exit 1
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

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$js = Join-Path $here "src\secret-diagnostic.js"
if (-not (Test-Path -LiteralPath $js)) {
  $js = Join-Path $here "secret-diagnostic.js"
}
if (-not (Test-Path -LiteralPath $js)) {
  Write-Diag "diagnostic" "missing-script"
  exit 1
}

if ($Compare) {
  Write-ListenerIdentity
  Write-Host "Type the password you use on the website sign-in page. It will not appear. Then press Enter."
  $candidateSecure = Read-Host -AsSecureString
  $candidatePlain = ""
  if ($null -eq $candidateSecure -or $candidateSecure.Length -eq 0) {
    Write-Diag "matchesOwner" "false"
    Write-Diag "matchesSession" "false"
    Write-Diag "candidate" "empty"
    Write-Diag "filesChanged" "false"
    exit 0
  }
  $candidatePlain = Convert-FromSecure $candidateSecure
  $compareNames = @("OWNER_PASSWORD", "SESSION_SECRET", "CPA_DIAG_CANDIDATE", "CPA_DIAG_MODE")
  try {
    Set-Item -Path Env:OWNER_PASSWORD -Value $ownerPlain
    Set-Item -Path Env:SESSION_SECRET -Value $sessionPlain
    Set-Item -Path Env:CPA_DIAG_CANDIDATE -Value $candidatePlain
    Set-Item -Path Env:CPA_DIAG_MODE -Value "compare"
    $child = & node $js
    foreach ($line in @($child)) {
      if ($line -match "^DIAG\|(matchesOwner|matchesSession|refused|compare|filesChanged)\|") {
        Write-Host $line
      }
    }
    if ($LASTEXITCODE -ne 0) { Write-Diag "compare" "failed" }
  } catch {
    Write-Diag "compare" "failed"
    exit 1
  } finally {
    foreach ($name in $compareNames) {
      Remove-Item -Path "Env:$name" -ErrorAction SilentlyContinue
    }
    $ownerPlain = $null
    $sessionPlain = $null
    $candidatePlain = $null
  }
  exit 0
}

$ownerParent = Get-SecretFlags $ownerPlain
$sessionParent = Get-SecretFlags $sessionPlain

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
