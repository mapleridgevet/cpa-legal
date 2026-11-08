# Reports how the resolve-only child behaved. It does not migrate, listen, or print child text.
param(
  [Parameter(Mandatory = $true)]
  [string]$Root,
  [Parameter(Mandatory = $true)]
  [string]$Migrate
)

$ErrorActionPreference = "Stop"
$LiveProgram = "C:\Users\naesm\cpa-oauth-service"
$LiveData = "C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth"
$LiveConnector = "C:\Users\naesm\quickbooks-card-connector"

function Assert-Contained {
  param([string]$Candidate)
  if ([string]::IsNullOrWhiteSpace($env:TEMP)) { throw "TEMP is not set." }
  $full = [System.IO.Path]::GetFullPath($Candidate)
  $sep = [string][System.IO.Path]::DirectorySeparatorChar
  $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd($sep)
  $probe = $full.TrimEnd($sep)
  if (-not ($probe.Equals($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or $probe.StartsWith($tempRoot + $sep, [StringComparison]::OrdinalIgnoreCase))) {
    throw "Refusing to use a folder outside TEMP."
  }
  foreach ($blocked in @($LiveProgram, $LiveData, $LiveConnector)) {
    $blockFull = [System.IO.Path]::GetFullPath($blocked).TrimEnd($sep)
    if ($probe.Equals($blockFull, [StringComparison]::OrdinalIgnoreCase) -or $probe.StartsWith($blockFull + $sep, [StringComparison]::OrdinalIgnoreCase)) {
      throw "Refusing to use a live CPA path."
    }
  }
  return $full
}

function Format-Bool {
  param([bool]$Value)
  if ($Value) { return "true" }
  return "false"
}

function Format-Units {
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return "none" }
  $count = [Math]::Min(4, $Text.Length)
  $parts = @()
  for ($i = 0; $i -lt $count; $i++) { $parts += [string]([int][char]$Text[$i]) }
  return ($parts -join ",")
}

function Get-MismatchIndex {
  param([string]$Actual, [string]$Expected)
  $limit = [Math]::Min($Actual.Length, $Expected.Length)
  for ($i = 0; $i -lt $limit; $i++) {
    if ($Actual[$i] -ne $Expected[$i]) { return $i }
  }
  if ($Actual.Length -ne $Expected.Length) { return $limit }
  return -1
}

$root = Assert-Contained $Root
$migrate = Assert-Contained $Migrate
if ((Split-Path -Leaf $migrate) -ne "migrate-secrets.ps1") { throw "Refusing a file that is not migrate-secrets.ps1." }
$scriptText = Get-Content -LiteralPath $migrate -Raw
$resolveAt = $scriptText.IndexOf('if ($ResolveOnly)')
$importAt = $scriptText.IndexOf("Import-Clixml")
if ($resolveAt -lt 0 -or $importAt -lt 0 -or $resolveAt -ge $importAt) {
  throw "Refusing to start a migration script without an early resolve-only exit."
}
if ($scriptText.IndexOf("CPA_MIGRATION_ISOLATED") -lt 0) { throw "Refusing a migration script without the isolation guard." }

if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root | Out-Null }
$root = Assert-Contained $root
$fixture = Join-Path $root ("resolve-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $fixture | Out-Null
$fixture = Assert-Contained $fixture
$expected = $fixture.TrimEnd([string][System.IO.Path]::DirectorySeparatorChar)

$previous = $env:CPA_MIGRATION_ISOLATED
$env:CPA_MIGRATION_ISOLATED = "1"
$exitCode = -1
$stdout = ""
$stderr = ""
$started = $false
$startFailed = $false
try {
  $argumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$migrate`" -DataDir `"$fixture`" -ResolveOnly"
  $start = New-Object System.Diagnostics.ProcessStartInfo
  $start.FileName = "powershell.exe"
  $start.Arguments = $argumentList
  $start.UseShellExecute = $false
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $start.CreateNoWindow = $true
  $start.StandardOutputEncoding = [System.Text.Encoding]::Unicode
  $start.StandardErrorEncoding = [System.Text.Encoding]::Unicode
  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $start
  [void]$process.Start()
  $started = $true
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  $process.WaitForExit()
  $exitCode = $process.ExitCode
  $stdout = [string]$stdoutTask.Result
  $stderr = [string]$stderrTask.Result
} catch {
  $startFailed = $true
} finally {
  if ($null -eq $previous) { Remove-Item Env:CPA_MIGRATION_ISOLATED -ErrorAction SilentlyContinue }
  else { $env:CPA_MIGRATION_ISOLATED = $previous }
}

$combined = $stdout + $stderr
$stdoutTrim = $stdout.Trim()
$combinedTrim = $combined.Trim()
Write-Host ("DIAG|childStarted|" + (Format-Bool $started))
Write-Host ("DIAG|startFailed|" + (Format-Bool $startFailed))
Write-Host "DIAG|exitCode|$exitCode"
Write-Host "DIAG|stdoutLength|$($stdout.Length)"
Write-Host "DIAG|stderrLength|$($stderr.Length)"
Write-Host "DIAG|expectedLength|$($expected.Length)"
Write-Host ("DIAG|stdoutTrimEquals|" + (Format-Bool $stdoutTrim.Equals($expected, [StringComparison]::OrdinalIgnoreCase)))
Write-Host ("DIAG|combinedTrimEquals|" + (Format-Bool $combinedTrim.Equals($expected, [StringComparison]::OrdinalIgnoreCase)))
Write-Host "DIAG|stdoutMismatchIndex|$(Get-MismatchIndex $stdoutTrim $expected)"
Write-Host "DIAG|combinedMismatchIndex|$(Get-MismatchIndex $combinedTrim $expected)"
Write-Host "DIAG|stdoutFirstUnits|$(Format-Units $stdout)"
Write-Host "DIAG|stderrFirstUnits|$(Format-Units $stderr)"
Write-Host "DIAG|stdoutNewlineCount|$((@($stdout.ToCharArray() | Where-Object { $_ -eq [char]10 })).Count)"
Write-Host ("DIAG|hasNullChar|" + (Format-Bool $combined.Contains([char]0)))
Write-Host ("DIAG|hasBom|" + (Format-Bool ($stdout.Length -gt 0 -and [int][char]$stdout[0] -eq 65279)))
Write-Host ("DIAG|hasMigrationStarted|" + (Format-Bool $combined.Contains("MIGRATION_STARTED")))
Write-Host ("DIAG|hasRefusingOutside|" + (Format-Bool $combined.Contains("Refusing isolated migration outside TEMP.")))
Write-Host ("DIAG|hasRefusingLive|" + (Format-Bool $combined.Contains("Refusing isolated migration on a live CPA path.")))
Write-Host ("DIAG|hasResolveOnlyBlocked|" + (Format-Bool $combined.Contains("ResolveOnly is only available for an isolated test.")))
Write-Host ("DIAG|hasClixml|" + (Format-Bool $combined.Contains("CLIXML")))
Write-Host ("DIAG|hasParserError|" + (Format-Bool $combined.Contains("ParserError")))
Write-Host ("DIAG|hasInvalidHandle|" + (Format-Bool $combined.Contains("The handle is invalid")))
Write-Host "DIAG|parentOpenedSecrets|false"
Write-Host "DIAG|listenerStarted|false"
exit 0
