import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { WINDOWS_ACL_APPLY_SCRIPT, WINDOWS_ACL_READ_SCRIPT, evaluateWindowsAclReport, restrictPrivate, saveRestricted } from "../src/acl.js";

test("Windows ACL failure deletes the token file and does not report success", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-acl-"));
  const filePath = path.join(dir, "qbo-tokens.json");
  assert.throws(() => saveRestricted(filePath, "{\"refreshToken\":\"refresh-token-VALUE-should-not-log\"}", {
    platform: "win32",
    user: "naesm",
    apply() {
      return { status: 1, stdout: "", stderr: "denied" };
    },
  }), /Windows ACL could not be restricted/);
  assert.equal(fs.existsSync(filePath), false);
});

test("Windows ACL must be one non-inherited Allow entry for the current user SID", () => {
  const owner = [
    "CURRENT|S-1-5-21-1590306728-1194262839-348735189-1001",
    "CURRENTNAME|NATESPC\\naesm",
    "PROTECTED|True",
    "ACCESSCOUNT|1",
    "ACE|S-1-5-21-1590306728-1194262839-348735189-1001|NATESPC\\naesm|FullControl|False|Allow",
  ].join("\n");
  assert.equal(evaluateWindowsAclReport(owner).ok, true);
  const byNameOnly = owner.replace("ACE|S-1-5-21-1590306728-1194262839-348735189-1001|", "ACE||");
  assert.equal(evaluateWindowsAclReport(byNameOnly).ok, true);
  const everyone = "CURRENT|S-1-5-21-1\nCURRENTNAME|NATESPC\\naesm\nPROTECTED|True\nACCESSCOUNT|1\nACE|S-1-1-0|Everyone|FullControl|False|Allow\n";
  assert.equal(evaluateWindowsAclReport(everyone).ok, false);
  const inherited = "CURRENT|S-1-5-21-1\nPROTECTED|True\nACCESSCOUNT|1\nACE|S-1-5-21-1|NATESPC\\naesm|FullControl|True|Allow\n";
  assert.equal(evaluateWindowsAclReport(inherited).ok, false);
  const extra = `${owner}\nACE|S-1-5-18|NT AUTHORITY\\SYSTEM|FullControl|False|Allow\n`.replace("ACCESSCOUNT|1", "ACCESSCOUNT|2");
  assert.equal(evaluateWindowsAclReport(extra).ok, false);
  const missingAce = "CURRENT|S-1-5-21-1\nPROTECTED|True\nACCESSCOUNT|0\n";
  assert.equal(evaluateWindowsAclReport(missingAce).ok, false);
  assert.match(missingAce && evaluateWindowsAclReport(missingAce).detail, /found 0/);
  const utf16 = Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(owner, "utf16le")]);
  assert.equal(evaluateWindowsAclReport(utf16).ok, true);
  assert.match(WINDOWS_ACL_READ_SCRIPT, /@\(\$acl\.Access\)/);
  assert.match(WINDOWS_ACL_READ_SCRIPT, /ACCESSCOUNT/);
  assert.match(WINDOWS_ACL_APPLY_SCRIPT, /AccessControlSections\]::Access/);
  assert.match(WINDOWS_ACL_APPLY_SCRIPT, /SetAccessControl\(\$acl\)/);
  assert.equal(WINDOWS_ACL_APPLY_SCRIPT.includes("Set-Acl"), false);
});

test("a verified owner-only ACL is accepted and a weak ACL is refused", () => {
  const calls = [];
  restrictPrivate("C:\\token-file", {
    platform: "win32",
    user: "naesm",
    directory: false,
    apply(script, target, user) {
      calls.push({ script, target, user });
      return { status: 0, stdout: "" };
    },
    read() {
      return { status: 0, stdout: "CURRENT|S-1-5-21-1-2-3-1001\nCURRENTNAME|NATESPC\\naesm\nPROTECTED|True\nACCESSCOUNT|1\nACE|S-1-5-21-1-2-3-1001|NATESPC\\naesm|FullControl|False|Allow\n" };
    },
  });
  assert.equal(calls[0].target, "C:\\token-file");
  assert.match(calls[0].script, /SetAccessRuleProtection/);
  assert.throws(() => restrictPrivate("C:\\token-file", {
    platform: "win32",
    user: "naesm",
    directory: false,
    apply() {
      return { status: 0, stdout: "" };
    },
    read() {
      return { status: 0, stdout: "CURRENT|S-1-5-21-1-2-3-1001\nPROTECTED|False\nACE|S-1-1-0|FullControl|True|Allow\n" };
    },
  }), /not owner-only/);
});
