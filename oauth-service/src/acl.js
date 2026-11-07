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
$path = $env:CPA_ACL_PATH
$item = Get-Item -LiteralPath $path -Force
$sections = [System.Security.AccessControl.AccessControlSections]::Access
$acl = $item.GetAccessControl($sections)
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Write-Output ('CURRENT|' + $current)
Write-Output ('PROTECTED|' + $acl.AreAccessRulesProtected)
foreach ($ace in $acl.Access) {
  if ($ace.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
    $aceSid = $ace.IdentityReference.Value
  } else {
    $aceSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  }
  Write-Output ('ACE|' + $aceSid + '|' + $ace.FileSystemRights + '|' + $ace.IsInherited + '|' + $ace.AccessControlType)
}
`.trim();

function runPowerShell(script, target, user) {
  return spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "-"], {
    input: script,
    encoding: "utf8",
    windowsHide: true,
    env: { ...process.env, CPA_ACL_PATH: target, CPA_ACL_USER: user },
  });
}

export function evaluateWindowsAclReport(stdout) {
  const lines = String(stdout || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const current = lines.find((line) => line.startsWith("CURRENT|"));
  const sid = current ? current.slice("CURRENT|".length) : "";
  const protectedLine = lines.find((line) => line.toUpperCase().startsWith("PROTECTED|"));
  const aces = lines.filter((line) => line.startsWith("ACE|")).map((line) => {
    const [, aceSid, rights, inherited, type] = line.split("|");
    return { sid: aceSid || "", rights: rights || "", inherited: inherited || "", type: type || "" };
  });
  const problems = [];
  if (!sid) problems.push("current user SID missing");
  if (!protectedLine || protectedLine.split("|")[1].toLowerCase() !== "true") {
    problems.push("inheritance is enabled");
  }
  if (aces.length !== 1) problems.push(`expected one access entry and found ${aces.length}`);
  const ace = aces[0];
  if ((ace?.sid || "") !== sid) problems.push(`identity SID is ${ace?.sid || "missing"}`);
  if ((ace?.inherited || "").toLowerCase() !== "false") problems.push("access entry is inherited");
  if ((ace?.type || "").toLowerCase() !== "allow") problems.push("access entry is not Allow");
  const rights = ace?.rights || "";
  const canReadAndWrite = rights === "FullControl" || (rights.includes("Read") && rights.includes("Write"));
  if (!canReadAndWrite) problems.push(`rights are ${rights || "missing"}`);
  return { ok: problems.length === 0, detail: problems.join("; ") || "owner-only" };
}

function applyAndVerifyWindowsAcl(target, user, options) {
  const apply = options.apply || ((script, pathName, account) => runPowerShell(script, pathName, account));
  const applied = apply(WINDOWS_ACL_APPLY_SCRIPT, target, user);
  if (!applied || applied.status !== 0) {
    throw new Error("Refusing to store tokens: Windows ACL could not be restricted");
  }
  const read = options.read || ((script, pathName, account) => runPowerShell(script, pathName, account));
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
