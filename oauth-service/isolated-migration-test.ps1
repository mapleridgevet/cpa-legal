# Runs the real migrate-secrets.ps1 against fake DPAPI secrets in a TEMP folder.
# It does not read the live install or the live data folder, and it does not listen.
param(
  [Parameter(Mandatory = $true)]
  [string]$Root
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$LiveProgram = "C:\Users\naesm\cpa-oauth-service"
$LiveData = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth"
$LiveConnector = "C:\Users\naesm\quickbooks-card-connector"
$FakePassword = "  isolated owner password  "
$FakeSession = "isolated-session-secret-value-32xy"
$FakeClientId = "fake-client-id-value"
$FakeClientSecret = "fake-client-secret-value"
$FakeRefresh = "isolated-fake-refresh-token"
$FakeAccess = "isolated-fake-access-token"
$FakeRealm = "isolated-fake-realm"

function Assert-IsolatedPath {
  param([string]$Candidate)
  $full = [System.IO.Path]::GetFullPath($Candidate)
  $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd("\")
  $probe = $full.TrimEnd("\")
  if (-not ($probe.Equals($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or $probe.StartsWith($tempRoot + "\", [StringComparison]::OrdinalIgnoreCase))) {
    throw "Refusing to use a folder outside TEMP."
  }
  foreach ($blocked in @($LiveProgram, $LiveData, $LiveConnector)) {
    $blockFull = [System.IO.Path]::GetFullPath($blocked).TrimEnd("\")
    if ($probe.Equals($blockFull, [StringComparison]::OrdinalIgnoreCase) -or $probe.StartsWith($blockFull + "\", [StringComparison]::OrdinalIgnoreCase)) {
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

function New-FakeSecrets {
  param([string]$Dir, [string]$SessionText, [switch]$IncludeIntuit)
  $bag = [ordered]@{
    OWNER_PASSWORD = (ConvertTo-SecureString $FakePassword -AsPlainText -Force)
    SESSION_SECRET = (ConvertTo-SecureString $SessionText -AsPlainText -Force)
  }
  if ($IncludeIntuit) {
    $bag.QBO_CLIENT_ID = ConvertTo-SecureString $FakeClientId -AsPlainText -Force
    $bag.QBO_CLIENT_SECRET = ConvertTo-SecureString $FakeClientSecret -AsPlainText -Force
  }
  $path = Join-Path $Dir "secrets.clixml"
  $bag | Export-Clixml -LiteralPath $path
  return $path
}

function Invoke-MigrationChild {
  param([string]$Dir, [switch]$ResolveOnly)
  $previousAction = $ErrorActionPreference
  $previous = $env:CPA_MIGRATION_ISOLATED
  $env:CPA_MIGRATION_ISOLATED = "1"
  $ErrorActionPreference = "Continue"
  $output = ""
  $code = 1
  try {
    $argumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$Migrate`""
    if (-not [string]::IsNullOrWhiteSpace($Dir)) { $argumentList += " -DataDir `"$Dir`"" }
    if ($ResolveOnly) { $argumentList += " -ResolveOnly" }
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = "powershell.exe"
    $start.Arguments = $argumentList
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    Set-ChildStreamEncoding $start
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    [void]$process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $code = $process.ExitCode
    $output = (ConvertFrom-ChildText ([string]$stdoutTask.Result)) + (ConvertFrom-ChildText ([string]$stderrTask.Result))
  } finally {
    $ErrorActionPreference = $previousAction
    if ($null -eq $previous) { Remove-Item Env:CPA_MIGRATION_ISOLATED -ErrorAction SilentlyContinue }
    else { $env:CPA_MIGRATION_ISOLATED = $previous }
  }
  foreach ($secret in @($FakePassword, $FakeSession, $FakeClientId, $FakeClientSecret, $FakeRefresh, $FakeAccess, $FakeRealm, "scrypt$")) {
    if ($output.Contains($secret)) { throw "Migration output contained secret material." }
  }
  $started = $output.Contains("MIGRATION_STARTED")
  if ($ResolveOnly -and $started) { throw "Path check continued into migration." }
  if (-not $ResolveOnly -and -not $started) { throw "Migration child did not start." }
  return @{ Code = $code; Output = $output }
}

function Assert-ChildResolution {
  param([string]$Dir)
  $resolved = Invoke-MigrationChild -Dir $Dir -ResolveOnly
  $expected = [System.IO.Path]::GetFullPath($Dir).TrimEnd("\")
  $actual = $resolved.Output.Trim()
  if ($resolved.Code -ne 0 -or -not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Migration child did not resolve inside the temp fixture."
  }
}

$root = Assert-IsolatedPath $Root
if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root | Out-Null }
$root = Assert-IsolatedPath $root
Assert-IsolatedPath $Here | Out-Null
$Migrate = Join-Path $Here "migrate-secrets.ps1"
if (-not (Test-Path -LiteralPath $Migrate)) { throw "migrate-secrets.ps1 is not beside this harness." }
Assert-IsolatedPath $Migrate | Out-Null
foreach ($rel in @(
  "decode-child-text.ps1",
  "src\owner-password-cli.js",
  "src\migrate-token-file.js",
  "src\token-key-cli.js",
  "src\token-check-cli.js",
  "src\protect-path.js"
)) {
  Assert-IsolatedPath (Join-Path $Here $rel) | Out-Null
}
$DecoderPath = Join-Path $Here "decode-child-text.ps1"
. $DecoderPath

$fixture = Join-Path $root ("fixture-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $fixture | Out-Null
Assert-IsolatedPath $fixture | Out-Null
Assert-ChildResolution $fixture
$outside = Join-Path (Split-Path -Parent ([System.IO.Path]::GetFullPath($env:TEMP))) ("cpa-not-temp-" + [guid]::NewGuid().ToString("n"))
$outsideRun = Invoke-MigrationChild -Dir $outside -ResolveOnly
if ($outsideRun.Code -eq 0 -or $outsideRun.Output.Contains("MIGRATION_STARTED")) { throw "A path outside TEMP was accepted." }
$liveRun = Invoke-MigrationChild -Dir $LiveData -ResolveOnly
if ($liveRun.Code -eq 0 -or $liveRun.Output.Contains("MIGRATION_STARTED")) { throw "The live data folder was accepted." }
$defaultRun = Invoke-MigrationChild -ResolveOnly
if ($defaultRun.Code -eq 0 -or $defaultRun.Output.Contains("MIGRATION_STARTED")) { throw "The default live data folder was accepted." }
Write-Host "ISOLATED|programUnderTemp|true"
Write-Host "ISOLATED|dataUnderFixture|true"
Write-Host "ISOLATED|livePaths|rejected"
Write-Host "ISOLATED|childResolvedUnderFixture|true"

$settings = '{"probe":"isolated"}'
$settingsPath = Join-Path $fixture "service-config.json"
Set-Content -LiteralPath $settingsPath -Value $settings -Encoding utf8
$settingsHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $settingsPath).Hash
New-FakeSecrets -Dir $fixture -SessionText $FakeSession -IncludeIntuit | Out-Null
$tokenPath = Join-Path $fixture "qbo-tokens.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$tokenJson = @{
  accessToken = $FakeAccess
  refreshToken = $FakeRefresh
  realmId = $FakeRealm
} | ConvertTo-Json -Compress
[System.IO.File]::WriteAllText($tokenPath, $tokenJson, $utf8NoBom)

$first = Invoke-MigrationChild $fixture
if ($first.Code -ne 0) { throw "First migration failed." }
$loaded = Import-Clixml -LiteralPath (Join-Path $fixture "secrets.clixml")
if ($loaded.OWNER_PASSWORD -is [System.Security.SecureString]) { throw "Reversible owner value remains." }
if ($loaded.SESSION_SECRET -isnot [System.Security.SecureString]) { throw "Session secret type changed." }
if ((Convert-FromSecure $loaded.SESSION_SECRET) -ne $FakeSession) { throw "Session secret value changed." }
if ($loaded.QBO_CLIENT_ID -isnot [System.Security.SecureString]) { throw "Client id was not preserved." }
if ((Convert-FromSecure $loaded.QBO_CLIENT_ID) -ne $FakeClientId) { throw "Client id value changed." }
if ($loaded.QBO_CLIENT_SECRET -isnot [System.Security.SecureString]) { throw "Client secret was not preserved." }
if ((Convert-FromSecure $loaded.QBO_CLIENT_SECRET) -ne $FakeClientSecret) { throw "Client secret value changed." }
if ($loaded.TOKEN_ENC_KEY -isnot [System.Security.SecureString]) { throw "Token key is missing." }
$keyPlain = Convert-FromSecure $loaded.TOKEN_ENC_KEY
$tokenText = Get-Content -LiteralPath $tokenPath -Raw
if ($tokenText.Contains($keyPlain) -or $tokenText.Contains($FakeRefresh) -or $tokenText.Contains($FakeAccess) -or $tokenText.Contains($FakeRealm)) {
  throw "Token file contains plaintext or the key."
}
$env:OWNER_PASSWORD = $FakePassword
$env:OWNER_PASSWORD_HASH = [string]$loaded.OWNER_PASSWORD_HASH
$exact = [string](& node (Join-Path $Here "src\owner-password-cli.js") verify)
$exactCode = $LASTEXITCODE
$env:OWNER_PASSWORD = $FakePassword.Trim()
$trimmed = [string](& node (Join-Path $Here "src\owner-password-cli.js") verify)
$trimmedCode = $LASTEXITCODE
Remove-Item Env:OWNER_PASSWORD -ErrorAction SilentlyContinue
Remove-Item Env:OWNER_PASSWORD_HASH -ErrorAction SilentlyContinue
foreach ($report in @($exact, $trimmed)) {
  foreach ($secret in @($FakePassword, $FakeSession, $FakeClientId, $FakeClientSecret, $FakeRefresh, $FakeAccess, $FakeRealm, "scrypt$")) {
    if ($report.Contains($secret)) { throw "Password check output contained secret material." }
  }
}
if ($exactCode -ne 0 -or $exact.Trim() -ne "match") { throw "Exact password did not verify." }
if ($trimmedCode -eq 0 -or $trimmed.Trim() -eq "match") { throw "Trimmed password was accepted." }
$env:TOKEN_ENC_KEY = $keyPlain
$env:CPA_EXPECT_REFRESH = $FakeRefresh
$env:CPA_EXPECT_ACCESS = $FakeAccess
$env:CPA_EXPECT_REALM = $FakeRealm
$tokenCheck = [string](& node (Join-Path $Here "src\token-check-cli.js") $tokenPath)
$tokenCheckCode = $LASTEXITCODE
Remove-Item Env:TOKEN_ENC_KEY -ErrorAction SilentlyContinue
Remove-Item Env:CPA_EXPECT_REFRESH -ErrorAction SilentlyContinue
Remove-Item Env:CPA_EXPECT_ACCESS -ErrorAction SilentlyContinue
Remove-Item Env:CPA_EXPECT_REALM -ErrorAction SilentlyContinue
$keyPlain = $null
foreach ($secret in @($FakePassword, $FakeSession, $FakeClientId, $FakeClientSecret, $FakeRefresh, $FakeAccess, $FakeRealm, "scrypt$")) {
  if ($tokenCheck.Contains($secret)) { throw "Token check output contained secret material." }
}
if ($tokenCheckCode -ne 0 -or $tokenCheck.Trim() -ne "match") { throw "Token decrypt failed." }
if (@(Get-ChildItem -LiteralPath $fixture -Recurse -Force -Filter "*.bak" -ErrorAction SilentlyContinue).Count -ne 0) { throw "A backup file remains." }
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $settingsPath).Hash -ne $settingsHash) { throw "Settings file changed." }
Write-Host "ISOLATED|exactPassword|true"
Write-Host "ISOLATED|trimmedDiffers|true"
Write-Host "ISOLATED|sessionKept|true"
Write-Host "ISOLATED|intuitKept|true"
Write-Host "ISOLATED|settingsUnchanged|true"
Write-Host "ISOLATED|keySeparate|true"
Write-Host "ISOLATED|tokenDecrypt|true"
Write-Host "ISOLATED|tokenPlaintextAbsent|true"
Write-Host "ISOLATED|backupAbsent|true"

$second = Invoke-MigrationChild $fixture
if ($second.Code -ne 0) { throw "Second migration failed." }
$again = Import-Clixml -LiteralPath (Join-Path $fixture "secrets.clixml")
if ($again.OWNER_PASSWORD -is [System.Security.SecureString]) { throw "Second run restored a reversible password." }
if ((Convert-FromSecure $again.SESSION_SECRET) -ne $FakeSession) { throw "Second run changed the session secret." }
Write-Host "ISOLATED|secondRun|true"

$shortDir = Join-Path $root ("short-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $shortDir | Out-Null
Assert-IsolatedPath $shortDir | Out-Null
Assert-ChildResolution $shortDir
$shortBag = [ordered]@{
  OWNER_PASSWORD = (ConvertTo-SecureString $FakePassword -AsPlainText -Force)
  SESSION_SECRET = (ConvertTo-SecureString "too-short" -AsPlainText -Force)
}
$shortPath = Join-Path $shortDir "secrets.clixml"
$shortBag | Export-Clixml -LiteralPath $shortPath
$before = (Get-FileHash -Algorithm SHA256 -LiteralPath $shortPath).Hash
$shortRun = Invoke-MigrationChild $shortDir
$after = (Get-FileHash -Algorithm SHA256 -LiteralPath $shortPath).Hash
if ($shortRun.Code -eq 0 -or $before -ne $after) { throw "Short session secret was not left unchanged." }
Write-Host "ISOLATED|shortSessionUnchanged|true"

$badDir = Join-Path $root ("badtoken-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $badDir | Out-Null
Assert-IsolatedPath $badDir | Out-Null
Assert-ChildResolution $badDir
New-FakeSecrets -Dir $badDir -SessionText $FakeSession | Out-Null
$badToken = Join-Path $badDir "qbo-tokens.json"
[System.IO.File]::WriteAllText($badToken, "{", $utf8NoBom)
$badBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $badToken).Hash
$badRun = Invoke-MigrationChild $badDir
$badAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $badToken).Hash
if ($badRun.Code -eq 0 -or $badBefore -ne $badAfter) { throw "Invalid token file was not kept." }
if (@(Get-ChildItem -LiteralPath $badDir -Recurse -Force -Filter "*.bak" -ErrorAction SilentlyContinue).Count -ne 0) { throw "Token failure left a backup." }
Write-Host "ISOLATED|invalidTokenKept|true"
Write-Host "ISOLATED|listenerStarted|false"
Write-Host ("ISOLATED|root|" + $root)
exit 0
