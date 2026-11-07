import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertOwnerOnlyFile } from "../src/acl.js";
import { createFileStateStore, sha256 } from "../src/stores.js";

test("file-backed state is single-use across a reload", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-state-"));
  const filePath = path.join(dir, "oauth-state.json");
  const state = "state-value-for-file-store-test";
  const first = createFileStateStore(filePath);
  first.put(sha256(state), { sid: "owner-a", exp: 5_000, used: false });
  const reloaded = createFileStateStore(filePath);
  assert.deepEqual(reloaded.consume(state, "owner-b", 1_000), { ok: false, reason: "session" });
  assert.deepEqual(reloaded.consume(state, "owner-a", 5_000), { ok: false, reason: "expired" });
  assert.deepEqual(reloaded.consume(state, "owner-a", 4_000), { ok: true });
  const again = createFileStateStore(filePath);
  assert.deepEqual(again.consume(state, "owner-a", 4_000), { ok: false, reason: "reused" });
  assertOwnerOnlyFile(filePath);
});
