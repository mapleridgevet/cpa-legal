import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { restrictPrivate, saveRestricted } from "../src/acl.js";

test("Windows ACL failure deletes the token file and does not report success", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-acl-"));
  const filePath = path.join(dir, "qbo-tokens.json");
  const calls = [];
  assert.throws(() => saveRestricted(filePath, "{\"refreshToken\":\"refresh-token-VALUE-should-not-log\"}", {
    platform: "win32",
    user: "naesm",
    restrict(target, extra) {
      calls.push({ target, directory: extra.directory });
      if (!extra.directory) {
        throw new Error("Refusing to store tokens: Windows ACL could not be restricted");
      }
    },
  }), /Windows ACL could not be restricted/);
  assert.equal(fs.existsSync(filePath), false);
  assert.equal(calls.some((call) => call.directory === true), true);
});

test("Windows restriction command grants only the current user", () => {
  const calls = [];
  restrictPrivate("C:\\token-file", {
    platform: "win32",
    user: "naesm",
    directory: false,
    run(command, args) {
      calls.push({ command, args });
      return { status: 0 };
    },
  });
  assert.equal(calls[0].command, "icacls");
  assert.deepEqual(calls[0].args, ["C:\\token-file", "/inheritance:r", "/grant:r", "naesm:(F)"]);
  assert.throws(() => restrictPrivate("C:\\token-file", {
    platform: "win32",
    user: "naesm",
    directory: false,
    run() {
      return { status: 1 };
    },
  }), /Windows ACL could not be restricted/);
});
