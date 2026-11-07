import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function writePrivate(filePath, contents) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, contents, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Windows ACLs are not Unix modes. The directory is still outside the repository.
  }
}

export function createMemoryStateStore() {
  const map = new Map();
  return {
    put(id, record) {
      map.set(id, { ...record });
    },
    consume(rawState, sid, now) {
      if (typeof rawState !== "string" || rawState.length < 16) return { ok: false, reason: "state" };
      const rec = map.get(sha256(rawState));
      if (!rec) return { ok: false, reason: "state" };
      if (rec.used) return { ok: false, reason: "reused" };
      if (rec.exp <= now) return { ok: false, reason: "expired" };
      if (rec.sid !== sid) return { ok: false, reason: "session" };
      rec.used = true;
      return { ok: true };
    },
  };
}

export function createFileStateStore(filePath) {
  const memory = createMemoryStateStore();
  const saved = new Map();
  if (fs.existsSync(filePath)) {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    for (const [id, record] of Object.entries(parsed)) {
      memory.put(id, record);
      saved.set(id, { ...record });
    }
  }
  function persist() {
    const dump = {};
    for (const [id, record] of saved.entries()) dump[id] = record;
    writePrivate(filePath, JSON.stringify(dump));
  }
  return {
    put(id, record) {
      memory.put(id, record);
      saved.set(id, { ...record });
      persist();
    },
    consume(rawState, sid, now) {
      const result = memory.consume(rawState, sid, now);
      if (typeof rawState === "string" && rawState.length >= 16) {
        const id = sha256(rawState);
        const current = saved.get(id);
        if (current && (result.ok || result.reason === "reused")) {
          current.used = true;
          saved.set(id, current);
          persist();
        }
      }
      return result;
    },
  };
}

export function createFileTokenStore(filePath) {
  return {
    kind: "file",
    filePath,
    load() {
      if (!fs.existsSync(filePath)) return null;
      return JSON.parse(fs.readFileSync(filePath, "utf8"));
    },
    save(record) {
      writePrivate(filePath, JSON.stringify(record));
    },
    clear() {
      if (fs.existsSync(filePath)) fs.rmSync(filePath);
    },
  };
}
