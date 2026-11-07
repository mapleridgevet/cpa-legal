import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createFileThrottleStore, createLoginThrottle } from "../src/login-throttle.js";

test("failed sign-ins are bounded and share one bucket", () => {
  let now = 1_000_000;
  const throttle = createLoginThrottle({ now: () => now, maxFailures: 5, windowMs: 1000 });
  for (let i = 0; i < 20; i += 1) {
    throttle.recordFailure(now);
  }
  assert.equal(throttle.failureCount() <= 5, true);
  assert.equal(throttle.check(now).locked, true);
  now += 1000;
  assert.equal(throttle.check(now).locked, false);
  assert.equal(throttle.failureCount(), 0);
});

test("a successful sign-in clears failures and a corrupt store stays locked", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-throttle-"));
  const file = path.join(dir, "login-throttle.json");
  fs.writeFileSync(file, JSON.stringify({ failures: ["not-a-list"], planted: "owner-password-value-16" }));
  let now = 5_000;
  const stored = createLoginThrottle({
    now: () => now,
    maxFailures: 5,
    windowMs: 1000,
    store: createFileThrottleStore(file),
  });
  assert.equal(stored.check(now).locked, true);
  const raw = fs.readFileSync(file, "utf8");
  assert.equal(raw.includes("owner-password-value-16"), false);
  assert.equal(raw.includes("not-a-list"), false);
  now += 1000;
  assert.equal(stored.check(now).locked, false);

  const memory = createLoginThrottle({ now: () => now, maxFailures: 3, windowMs: 5000 });
  memory.recordFailure(now);
  memory.recordFailure(now);
  assert.equal(memory.recordSuccess(now).locked, false);
  assert.equal(memory.failureCount(), 0);
});
