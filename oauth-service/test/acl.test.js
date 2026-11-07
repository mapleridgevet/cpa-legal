import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { WINDOWS_ACL_APPLY_SCRIPT, evaluateWindowsAclReport, restrictPrivate, saveRestricted } from "../src/acl.js";

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
  const owner = "CURRENT|S-1-5-21-1-2-3-1001\nPROTECTED|True\nACE|S-1-5-21-1-2-3-1001|FullControl|False|Allow\n";
  assert.equal(evaluateWindowsAclReport(owner).ok, true);
  const everyone = "CURRENT|S-1-5-21-1-2-3-1001\nPROTECTED|True\nACE|S-1-1-0|FullControl|False|Allow\n";
  assert.equal(evaluateWindowsAclReport(everyone).ok, false);
  const inherited = "CURRENT|S-1-5-21-1-2-3-1001\nPROTECTED|True\nACE|S-1-5-32-545|ReadAndExecute|True|Allow\n";
  assert.equal(evaluateWindowsAclReport(inherited).ok, false);
  const extra = "CURRENT|S-1-5-21-1-2-3-1001\nPROTECTED|True\nACE|S-1-5-21-1-2-3-1001|FullControl|False|Allow\nACE|S-1-5-18|FullControl|False|Allow\n";
  assert.equal(evaluateWindowsAclReport(extra).ok, false);
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
      return { status: 0, stdout: "CURRENT|S-1-5-21-1-2-3-1001\nPROTECTED|True\nACE|S-1-5-21-1-2-3-1001|FullControl|False|Allow\n" };
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
