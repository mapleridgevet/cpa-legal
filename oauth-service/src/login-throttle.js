import fs from "node:fs";
import { saveRestricted } from "./acl.js";

export const LOGIN_FAILURE_LIMIT = 5;
export const LOGIN_WINDOW_MS = 15 * 60 * 1000;

export function createFileThrottleStore(filePath) {
  return {
    load() {
      if (!fs.existsSync(filePath)) return null;
      return JSON.parse(fs.readFileSync(filePath, "utf8"));
    },
    save(record) {
      const failures = Array.isArray(record.failures) ? record.failures.slice(-LOGIN_FAILURE_LIMIT) : [];
      const corruptLockUntil = Number.isInteger(record.corruptLockUntil) ? record.corruptLockUntil : 0;
      saveRestricted(filePath, JSON.stringify({ failures, corruptLockUntil }));
    },
  };
}

export function createLoginThrottle(options = {}) {
  const now = options.now || (() => Date.now());
  const maxFailures = options.maxFailures ?? LOGIN_FAILURE_LIMIT;
  const windowMs = options.windowMs ?? LOGIN_WINDOW_MS;
  const store = options.store || null;
  let failures = [];
  let corruptLockUntil = 0;

  function persist() {
    if (!store) return;
    try {
      store.save({ failures: failures.slice(-maxFailures), corruptLockUntil });
    } catch {
      // The in-memory count still applies for this process.
    }
  }

  function validFailureList(value) {
    return Array.isArray(value)
      && value.length <= maxFailures
      && value.every((item) => Number.isInteger(item) && item >= 0);
  }

  if (store) {
    let parsed = null;
    let corrupt = false;
    try {
      parsed = store.load();
    } catch {
      corrupt = true;
    }
    if (!corrupt && parsed != null) {
      const lockUntil = parsed.corruptLockUntil;
      if (lockUntil != null && !(Number.isInteger(lockUntil) && lockUntil >= 0)) corrupt = true;
      if (!validFailureList(parsed.failures)) corrupt = true;
      if (!corrupt) {
        failures = parsed.failures.slice(-maxFailures);
        corruptLockUntil = lockUntil || 0;
      }
    }
    if (corrupt) {
      failures = [];
      corruptLockUntil = now() + windowMs;
      persist();
    }
  }

  function prune(at) {
    failures = failures.filter((stamp) => at - stamp < windowMs).slice(-maxFailures);
  }

  function status(at) {
    if (corruptLockUntil > at) {
      return { locked: true, retryAfterMs: corruptLockUntil - at };
    }
    prune(at);
    if (failures.length >= maxFailures) {
      return { locked: true, retryAfterMs: Math.max(0, failures[0] + windowMs - at) };
    }
    return { locked: false, retryAfterMs: 0 };
  }

  return {
    check(at = now()) {
      return status(at);
    },
    recordFailure(at = now()) {
      const current = status(at);
      if (current.locked) return current;
      failures.push(at);
      failures = failures.slice(-maxFailures);
      persist();
      return status(at);
    },
    recordSuccess(at = now()) {
      failures = [];
      if (corruptLockUntil > at) return status(at);
      corruptLockUntil = 0;
      persist();
      return status(at);
    },
    failureCount() {
      return failures.length;
    },
  };
}
