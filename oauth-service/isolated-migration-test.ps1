# Isolated fake-data check for DPAPI export and token encryption.
# It does not read or write the live program or the live data folder.
# It does not listen on a port.
param(
  [Parameter(Mandatory = $true)]
  [string]$Root
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$LiveProgram = "C:\Users\naesm\cpa-oauth-service"
$LiveData = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth"
$LiveConnector = "C:\Users\naesm\quickbooks-card-connector"
$FakePassword = "isolated-test-password1"
$FakeSession = "isolated-test-session-secret-32xy"
$FakeRefresh = "isolated-fake-refresh-token"
$FakeAccess = "isolated-fake-access-token"
$FakeRealm = "isolated-fake-realm"

function Assert-IsolatedPath {
  param([string]$Candidate)
  $full = [System.IO.Path]::GetFullPath($Candidate)
  $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
  if (-not $full.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use a folder outside TEMP."
  }
  foreach ($blocked in @($LiveProgram, $LiveData, $LiveConnector)) {
    $blockFull = [System.IO.Path]::GetFullPath($blocked)
    if ($full.Equals($blockFull, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($blockFull + "\", [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to use a live CPA path."
    }
  }
  return $full
}

function Convert-FromSecure {
  param([Security.SecureString]$Value)
  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

$root = Assert-IsolatedPath $Root
$fixture = Join-Path $root "fixture"
if (Test-Path -LiteralPath $fixture) { throw "Refusing to reuse an existing fixture folder." }
New-Item -ItemType Directory -Path $fixture | Out-Null
Assert-IsolatedPath $fixture | Out-Null

$secretPath = Join-Path $fixture "secrets.clixml"
$tokenPath = Join-Path $fixture "qbo-tokens.json"
$ownerSecure = ConvertTo-SecureString $FakePassword -AsPlainText -Force
$sessionSecure = ConvertTo-SecureString $FakeSession -AsPlainText -Force
$bag = [ordered]@{
  OWNER_PASSWORD = $ownerSecure
  SESSION_SECRET = $sessionSecure
}
$bag | Export-Clixml -LiteralPath $secretPath
Set-Content -LiteralPath $tokenPath -Value (@{ accessToken = $FakeAccess; refreshToken = $FakeRefresh; realmId = $FakeRealm } | ConvertTo-Json) -Encoding utf8

$loaded = Import-Clixml -LiteralPath $secretPath
if ($loaded.OWNER_PASSWORD -isnot [System.Security.SecureString]) { throw "DPAPI owner value was not a SecureString." }
if ($loaded.SESSION_SECRET -isnot [System.Security.SecureString]) { throw "DPAPI session value was not a SecureString." }
$ownerPlain = Convert-FromSecure $loaded.OWNER_PASSWORD
if ($ownerPlain -ne $FakePassword) { throw "DPAPI owner round-trip failed." }

$env:OWNER_PASSWORD = $ownerPlain
$hash = [string](& node (Join-Path $Here "src\owner-password-cli.js") hash)
if ($LASTEXITCODE -ne 0 -or -not $hash.StartsWith("scrypt$")) { throw "Hash step failed." }
$env:OWNER_PASSWORD_HASH = $hash
$verify = [string](& node (Join-Path $Here "src\owner-password-cli.js") verify)
Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0 -or $verify.Trim() -ne "match") { throw "Hash verification failed." }

$keyText = [string](& node (Join-Path $Here "src\token-key-cli.js"))
$env:TOKEN_ENC_KEY = $keyText
$tokenResult = [string](& node (Join-Path $Here "src\migrate-token-file.js") $tokenPath)
Remove-Item Env:TOKEN_ENC_KEY -ErrorAction SilentlyContinue
if ($LASTEXITCODE -ne 0 -or $tokenResult.Trim() -ne "encrypted") { throw "Token encryption failed." }
$tokenText = Get-Content -LiteralPath $tokenPath -Raw
if ($tokenText.Contains($FakeRefresh) -or $tokenText.Contains($FakeAccess) -or $tokenText.Contains($FakeRealm)) {
  throw "Token file still contains plaintext."
}

$migratedPath = Join-Path $fixture "secrets.migrated.clixml"
$migrated = [ordered]@{
  OWNER_PASSWORD_HASH = $hash
  SESSION_SECRET = $loaded.SESSION_SECRET
  TOKEN_ENC_KEY = (ConvertTo-SecureString $keyText -AsPlainText -Force)
}
$migrated | Export-Clixml -LiteralPath $migratedPath
$again = Import-Clixml -LiteralPath $migratedPath
if ($again.OWNER_PASSWORD -is [System.Security.SecureString]) { throw "Reversible owner value remains." }
if (-not ([string]$again.OWNER_PASSWORD_HASH).StartsWith("scrypt$")) { throw "Migrated hash missing." }
if ($again.SESSION_SECRET -isnot [System.Security.SecureString]) { throw "Session secret was not preserved." }

Write-Host "ISOLATED|dpapiRoundTrip|true"
Write-Host "ISOLATED|passwordHash|verified"
Write-Host "ISOLATED|tokenFile|encrypted"
Write-Host "ISOLATED|reversibleRemoved|true"
Write-Host "ISOLATED|sessionKept|true"
Write-Host "ISOLATED|livePaths|untouched"
Write-Host ("ISOLATED|fixture|" + $fixture)
exit 0
