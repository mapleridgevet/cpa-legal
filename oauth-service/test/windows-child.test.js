import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { WINDOWS_ACL_INDEX_READ_SCRIPT, restrictPrivate, saveRestricted } from "../src/acl.js";
import { diagnoseDirectory } from "../src/acl-diagnostic.js";

const FAKE_POWERSHELL = `
const fs = require("node:fs");
const args = process.argv.slice(2);
if (args.includes("-Command") || !args.includes("-EncodedCommand")) {
  process.stderr.write("stdin command mode dropped the loop\\n");
  process.exit(4);
}
const script = Buffer.from(args[args.indexOf("-EncodedCommand") + 1], "base64").toString("utf16le");
if (!script.includes("foreach") && !script.includes("for (")) {
  process.stderr.write("encoded script has no loop\\n");
  process.exit(5);
}
const mode = process.env.FAKE_PS_MODE || "utf8";
if (script.includes("B_COUNT")) {
  fs.writeSync(1, "B_PROTECTED|True\\nB_COUNT|1\\nB_ACCOUNT|0|NATESPC\\\\naesm\\nB_RIGHTS|0|FullControl\\nB_INHERITED|0|False\\nB_TYPE|0|Allow\\nB_DONE\\n");
  process.exit(0);
}
if (mode === "fail-apply" && script.includes("SetAccessControl")) process.exit(2);
if (script.includes("SetAccessControl")) process.exit(0);
if (mode === "read-fail") process.exit(3);
const report = process.env.FAKE_PS_REPORT || "";
const body = mode === "utf16"
  ? Buffer.concat([Buffer.from([0xFF, 0xFE]), Buffer.from(report, "utf16le")])
  : Buffer.from(report, "utf8");
fs.writeSync(1, body);
process.exit(0);
`;

const goodReport = [
  "CURRENT|S-1-5-21-1590306728-1194262839-348735189-1001",
  "CURRENTNAME|NATESPC\\naesm",
  "PROTECTED|True",
  "ACCESSCOUNT|1",
  "ACE|S-1-5-21-1590306728-1194262839-348735189-1001|NATESPC\\naesm|FullControl|False|Allow",
].join("\n");

function childOptions(mode, report = goodReport) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-fake-ps-"));
  const fixture = path.join(dir, "fake-powershell.cjs");
  fs.writeFileSync(fixture, `#!/usr/bin/env node\n${FAKE_POWERSHELL}`);
  fs.chmodSync(fixture, 0o755);
  return {
    platform: "win32",
    user: "naesm",
    command: fixture,
    env: { FAKE_PS_MODE: mode, FAKE_PS_REPORT: report },
  };
}

test("the Windows child-process path accepts UTF-8 and UTF-16 reports", () => {
  assert.doesNotThrow(() => restrictPrivate("C:\\data", { ...childOptions("utf8"), directory: true }));
  assert.doesNotThrow(() => restrictPrivate("C:\\data", { ...childOptions("utf16"), directory: true }));
});

test("the Windows child-process path stays fail-closed for empty and failed reports", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-child-"));
  const filePath = path.join(dir, "qbo-tokens.json");
  assert.throws(() => saveRestricted(filePath, "{\"refreshToken\":\"hidden\"}", childOptions(
    "utf8",
    "CURRENT|S-1\nCURRENTNAME|NATESPC\\naesm\nPROTECTED|True\nACCESSCOUNT|0\n",
  )), /not owner-only/);
  assert.equal(fs.existsSync(filePath), false);
  assert.throws(() => restrictPrivate("C:\\data", childOptions("fail-apply")), /could not be restricted/);
  assert.throws(() => restrictPrivate("C:\\data", childOptions("read-fail")), /could not be read back/);
});

test("the same child path preserves a count-without-ACE report for diagnosis", () => {
  const partial = "CURRENT|S-1-5-21-1590306728-1194262839-348735189-1001\nCURRENTNAME|NATESPC\\naesm\nPROTECTED|True\nACCESSCOUNT|1\n";
  let seen = "";
  assert.throws(() => restrictPrivate("C:\\data", {
    ...childOptions("utf8", partial),
    apply(script) {
      seen = script;
      return { status: 0, stdout: "" };
    },
  }), /not owner-only/);
  assert.match(seen, /SetAccessControl/);
});

test("directory diagnostic uses the child process and does not change the ACL", () => {
  const output = diagnoseDirectory("C:\\Users\\naesm\\AppData\\Local\\MapleRidge\\cpa-oauth", childOptions(
    "utf8",
    "CURRENT|S-1-5-21-1590306728-1194262839-348735189-1001\nCURRENTNAME|NATESPC\\naesm\nPROTECTED|True\nACCESSCOUNT|1\n",
  ));
  assert.match(output, /BEGIN\|installer-read/);
  assert.match(output, /ACCESSCOUNT\|1/);
  assert.match(output, /found 0/);
  assert.match(output, /BEGIN\|index-read/);
  assert.match(output, /B_ACCOUNT\|0\|NATESPC\\\\naesm/);
  assert.equal(WINDOWS_ACL_INDEX_READ_SCRIPT.includes("SetAccessControl"), false);
});

test("packaged Windows launcher does not pass an invalid spawn encoding", () => {
  const source = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src", "acl.js"), "utf8");
  assert.equal(source.includes("encoding: \"buffer\"") || source.includes("encoding: 'buffer'"), false);
  assert.match(source, /-EncodedCommand/);
  assert.equal(source.includes('"-Command", "-"'), false);
});
