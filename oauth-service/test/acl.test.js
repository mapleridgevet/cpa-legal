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

test("Windows ACL must be one non-inherited Allow entry for the owner", () => {
  assert.equal(evaluateWindowsAclReport("PROTECTED|True\nNATESPC\\naesm|FullControl|False|Allow\n", "naesm").ok, true);
  const everyone = evaluateWindowsAclReport("PROTECTED|True\nEveryone|FullControl|False|Allow\n", "naesm");
  assert.equal(everyone.ok, false);
  const inherited = evaluateWindowsAclReport("PROTECTED|True\nBUILTIN\\Users|ReadAndExecute|True|Allow\n", "naesm");
  assert.equal(inherited.ok, false);
  const extra = evaluateWindowsAclReport(
    "PROTECTED|True\nNATESPC\\naesm|FullControl|False|Allow\nNT AUTHORITY\\SYSTEM|FullControl|False|Allow\n",
    "naesm",
  );
  assert.equal(extra.ok, false);
  assert.match(WINDOWS_ACL_APPLY_SCRIPT, /SetAccessRuleProtection\(\$true, \$false\)/);
  assert.equal(WINDOWS_ACL_APPLY_SCRIPT.includes("Everyone"), false);
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
      return { status: 0, stdout: "PROTECTED|True\nNATESPC\\naesm|FullControl|False|Allow\n" };
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
      return { status: 0, stdout: "PROTECTED|False\nEveryone|FullControl|True|Allow\n" };
    },
  }), /not owner-only/);
});
