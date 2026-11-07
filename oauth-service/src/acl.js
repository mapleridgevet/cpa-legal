import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

// DACL only. Set-Acl persists the SACL too and demands SeSecurityPrivilege, which a normal
// user does not have. GetAccessControl(Access) and SetAccessControl write the discretionary ACL.
export const WINDOWS_ACL_APPLY_SCRIPT = `
$ErrorActionPreference = 'Stop'
$path = $env:CPA_ACL_PATH
$item = Get-Item -LiteralPath $path -Force
$sections = [System.Security.AccessControl.AccessControlSections]::Access
$acl = $item.GetAccessControl($sections)
$acl.SetAccessRuleProtection($true, $false)
foreach ($identity in @($acl.Access | ForEach-Object { $_.IdentityReference })) {
  $acl.PurgeAccessRules($identity)
}
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($item.PSIsContainer) {
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
} else {
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}
$acl.AddAccessRule($rule)
$item.SetAccessControl($acl)
`.trim();

export const WINDOWS_ACL_READ_SCRIPT = `
$ErrorActionPreference = 'Stop'
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
[Console]::OutputEncoding = $OutputEncoding
$path = $env:CPA_ACL_PATH
$item = Get-Item -LiteralPath $path -Force
$sections = [System.Security.AccessControl.AccessControlSections]::Access
$acl = $item.GetAccessControl($sections)
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Output ('CURRENT|' + $current.User.Value)
Write-Output ('CURRENTNAME|' + $current.Name)
Write-Output ('PROTECTED|' + $acl.AreAccessRulesProtected)
$entries = @($acl.Access)
Write-Output ('ACCESSCOUNT|' + $entries.Count)
foreach ($ace in $entries) {
  $account = [string]$ace.IdentityReference
  $sidText = ''
  try {
    if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
      $sidText = [string]$ace.IdentityReference.Value
    } else {
      $sidText = [string]$ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
  } catch {
    $sidText = ''
  }
  Write-Output ((@('ACE', $sidText, $account, [string]$ace.FileSystemRights, [string]$ace.IsInherited, [string]$ace.AccessControlType) -join '|'))
}
`.trim();

export const WINDOWS_ACL_INDEX_READ_SCRIPT = `
$ErrorActionPreference = 'Continue'
$path = $env:CPA_ACL_PATH
$item = Get-Item -LiteralPath $path -Force
$sections = [System.Security.AccessControl.AccessControlSections]::Access
$acl = $item.GetAccessControl($sections)
$entries = @($acl.Access)
[Console]::Out.WriteLine('B_PROTECTED|' + $acl.AreAccessRulesProtected)
[Console]::Out.WriteLine('B_COUNT|' + $entries.Count)
for ($i = 0; $i -lt $entries.Count; $i++) {
  $ace = $entries[$i]
  [Console]::Out.WriteLine('B_ACCOUNT|' + $i + '|' + $ace.IdentityReference)
  [Console]::Out.WriteLine('B_RIGHTS|' + $i + '|' + $ace.FileSystemRights)
  [Console]::Out.WriteLine('B_INHERITED|' + $i + '|' + $ace.IsInherited)
  [Console]::Out.WriteLine('B_TYPE|' + $i + '|' + $ace.AccessControlType)
}
[Console]::Out.WriteLine('B_DONE')
`.trim();

export function decodePowerShellStdout(stdout) {
  const buffer = Buffer.isBuffer(stdout) ? stdout : Buffer.from(String(stdout ?? ""), "utf8");
  if (buffer.length >= 2 && buffer[0] === 0xFF && buffer[1] === 0xFE) return buffer.subarray(2).toString("utf16le");
  if (buffer.length >= 4 && buffer[1] === 0x00 && buffer[3] === 0x00) return buffer.toString("utf16le");
  return buffer.toString("utf8").replace(/^\uFEFF/, "");
}

export function encodePowerShellCommand(script) {
  const text = script.endsWith("\n") ? script : `${script}\n`;
  return Buffer.from(text, "utf16le").toString("base64");
}

function runPowerShell(script, target, user, options = {}) {
  const command = options.command || "powershell.exe";
  const args = options.args || ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(script)];
  const result = spawnSync(command, args, {
    windowsHide: true,
    env: { ...process.env, ...options.env, CPA_ACL_PATH: target, CPA_ACL_USER: user },
  });
  if (!result) return result;
  const stdoutRaw = Buffer.isBuffer(result.stdout) ? result.stdout : Buffer.from(result.stdout || "");
  const stderrRaw = Buffer.isBuffer(result.stderr) ? result.stderr : Buffer.from(result.stderr || "");
  return {
    ...result,
    stdoutRaw,
    stderrRaw,
    stdout: decodePowerShellStdout(stdoutRaw),
    stderr: decodePowerShellStdout(stderrRaw),
  };
}

export function captureWindowsAclRead(target, script, options = {}) {
  return runPowerShell(script, target, options.user || process.env.USERNAME || "", options);
}

export function evaluateWindowsAclReport(stdout) {
  const lines = decodePowerShellStdout(stdout).split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const current = lines.find((line) => line.startsWith("CURRENT|"));
  const sid = current ? current.slice("CURRENT|".length) : "";
  const currentNameLine = lines.find((line) => line.startsWith("CURRENTNAME|"));
  const currentName = currentNameLine ? currentNameLine.slice("CURRENTNAME|".length) : "";
  const protectedLine = lines.find((line) => line.toUpperCase().startsWith("PROTECTED|"));
  const countLine = lines.find((line) => line.startsWith("ACCESSCOUNT|"));
  const aces = lines.filter((line) => line.startsWith("ACE|")).map((line) => {
    const parts = line.split("|");
    if (parts.length >= 6) {
      return { sid: parts[1] || "", account: parts[2] || "", rights: parts[3] || "", inherited: parts[4] || "", type: parts[5] || "" };
    }
    return { sid: parts[1] || "", account: "", rights: parts[2] || "", inherited: parts[3] || "", type: parts[4] || "" };
  });
  const problems = [];
  if (!sid && !currentName) problems.push("current user SID missing");
  if (!protectedLine || protectedLine.split("|")[1].toLowerCase() !== "true") problems.push("inheritance is enabled");
  if (countLine && Number(countLine.slice("ACCESSCOUNT|".length)) !== aces.length) {
    problems.push(`access count ${countLine.slice("ACCESSCOUNT|".length)} does not match ${aces.length} reported entries`);
  }
  if (aces.length !== 1) problems.push(`expected one access entry and found ${aces.length}`);
  const ace = aces[0];
  const sidOk = Boolean(sid) && ace?.sid === sid;
  const nameOk = Boolean(currentName) && (ace?.account || "").toLowerCase() === currentName.toLowerCase();
  if (!sidOk && !nameOk) problems.push(`identity SID is ${ace?.sid || "missing"}`);
  if ((ace?.inherited || "").toLowerCase() !== "false") problems.push("access entry is inherited");
  if ((ace?.type || "").toLowerCase() !== "allow") problems.push("access entry is not Allow");
  const rights = ace?.rights || "";
  const canReadAndWrite = rights === "FullControl" || rights === "2032127" || (rights.includes("Read") && rights.includes("Write"));
  if (!canReadAndWrite) problems.push(`rights are ${rights || "missing"}`);
  return { ok: problems.length === 0, detail: problems.join("; ") || "owner-only" };
}

function applyAndVerifyWindowsAcl(target, user, options) {
  const apply = options.apply || ((script, pathName, account) => runPowerShell(script, pathName, account, options));
  const applied = apply(WINDOWS_ACL_APPLY_SCRIPT, target, user);
  if (!applied || applied.status !== 0) {
    throw new Error("Refusing to store tokens: Windows ACL could not be restricted");
  }
  const read = options.read || ((script, pathName, account) => runPowerShell(script, pathName, account, options));
  const report = read(WINDOWS_ACL_READ_SCRIPT, target, user);
  if (!report || report.status !== 0) {
    throw new Error("Refusing to store tokens: Windows ACL could not be read back");
  }
  const verdict = evaluateWindowsAclReport(report.stdout);
  if (!verdict.ok) {
    throw new Error(`Refusing to store tokens: Windows ACL is not owner-only (${verdict.detail})`);
  }
}

export function restrictPrivate(target, options = {}) {
  const platform = options.platform || process.platform;
  const directory = options.directory === true;
  if (platform !== "win32") {
    fs.chmodSync(target, directory ? 0o700 : 0o600);
    return;
  }
  const user = options.user || process.env.USERNAME || "";
  if (!/^[A-Za-z0-9 ._$()-]+$/.test(user)) {
    throw new Error("Refusing to store tokens: Windows user name is unavailable");
  }
  applyAndVerifyWindowsAcl(target, user, options);
}

export function assertOwnerOnlyFile(filePath) {
  if (process.platform !== "win32") {
    const mode = fs.statSync(filePath).mode & 0o777;
    if (mode !== 0o600) {
      throw new Error(`Unix mode ${mode.toString(8)} is not 0600`);
    }
    return;
  }
  const user = process.env.USERNAME || "";
  const report = runPowerShell(WINDOWS_ACL_READ_SCRIPT, filePath, user);
  if (!report || report.status !== 0) {
    throw new Error("Windows ACL could not be read back");
  }
  const verdict = evaluateWindowsAclReport(report.stdout);
  if (!verdict.ok) {
    throw new Error(`Windows ACL is not owner-only (${verdict.detail})`);
  }
}

export function saveRestricted(filePath, contents, options = {}) {
  const restrict = options.restrict || ((target, extra) => restrictPrivate(target, { ...options, ...extra }));
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true });
  restrict(directory, { directory: true });
  const tmp = `${filePath}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, contents, { mode: 0o600 });
    restrict(tmp, { directory: false });
    fs.renameSync(tmp, filePath);
    restrict(filePath, { directory: false });
  } catch (error) {
    fs.rmSync(tmp, { force: true });
    fs.rmSync(filePath, { force: true });
    throw error;
  }
}
