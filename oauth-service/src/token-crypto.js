import crypto from "node:crypto";
import fs from "node:fs";
import { saveRestricted } from "./acl.js";

const AAD = Buffer.from("cpa-oauth-token-record-v1");

export function assertTokenKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("Refusing to use tokens: encryption key is missing");
}

export function encryptTokenRecord(record, key) {
  assertTokenKey(key);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(AAD);
  const ct = Buffer.concat([cipher.update(JSON.stringify(record), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { v: 1, alg: "A256GCM", iv: iv.toString("base64"), tag: tag.toString("base64"), ct: ct.toString("base64") };
}

export function decryptTokenRecord(envelope, key) {
  assertTokenKey(key);
  if (!envelope || envelope.v !== 1 || envelope.alg !== "A256GCM") throw new Error("Refusing to read tokens");
  const iv = Buffer.from(String(envelope.iv || ""), "base64");
  const tag = Buffer.from(String(envelope.tag || ""), "base64");
  const ct = Buffer.from(String(envelope.ct || ""), "base64");
  if (iv.length !== 12 || tag.length !== 16 || ct.length === 0) throw new Error("Refusing to read tokens");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(AAD);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(plain.toString("utf8"));
}

export function classifyTokenPayload(raw) {
  let parsed;
  try {
    parsed = JSON.parse(String(raw));
  } catch {
    return "invalid";
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "invalid";
  if (typeof parsed.refreshToken === "string" || typeof parsed.accessToken === "string" || typeof parsed.realmId === "string") {
    return "plaintext";
  }
  if (parsed.v === 1 && parsed.alg === "A256GCM" && parsed.iv && parsed.tag && parsed.ct) return "encrypted";
  return "invalid";
}

export function migratePlaintextToken(raw, key) {
  const kind = classifyTokenPayload(raw);
  if (kind === "encrypted") return { action: "unchanged" };
  if (kind !== "plaintext") throw new Error("Refusing to migrate tokens");
  const record = JSON.parse(raw);
  const envelope = encryptTokenRecord(record, key);
  const round = decryptTokenRecord(envelope, key);
  if (round.refreshToken !== record.refreshToken || round.accessToken !== record.accessToken || round.realmId !== record.realmId) {
    throw new Error("Refusing to migrate tokens");
  }
  const encoded = JSON.stringify(envelope);
  for (const value of [record.refreshToken, record.accessToken, record.realmId]) {
    if (typeof value === "string" && value.length >= 8 && encoded.includes(value)) {
      throw new Error("Refusing to migrate tokens");
    }
  }
  return { action: "encrypt", envelope };
}

export function createProtectedTokenStore(filePath, key) {
  return {
    filePath,
    load() {
      if (!fs.existsSync(filePath)) return null;
      const raw = fs.readFileSync(filePath, "utf8");
      const kind = classifyTokenPayload(raw);
      if (kind === "plaintext") throw new Error("Refusing to read plaintext tokens");
      if (kind !== "encrypted") throw new Error("Refusing to read tokens");
      if (!key) throw new Error("Refusing to read tokens: encryption key is missing");
      return decryptTokenRecord(JSON.parse(raw), key);
    },
    save(record) {
      assertTokenKey(key);
      const envelope = encryptTokenRecord(record, key);
      saveRestricted(filePath, JSON.stringify(envelope));
    },
    clear() {
      if (!key) throw new Error("Refusing to delete tokens: encryption key is missing");
      if (fs.existsSync(filePath)) fs.rmSync(filePath);
    },
  };
}

export function migrateTokenFile(filePath, key) {
  assertTokenKey(key);
  if (!fs.existsSync(filePath)) return "absent";
  const original = fs.readFileSync(filePath);
  const result = migratePlaintextToken(original.toString("utf8"), key);
  if (result.action === "unchanged") return "already-encrypted";
  const temp = `${filePath}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  try {
    saveRestricted(temp, JSON.stringify(result.envelope));
    const check = decryptTokenRecord(JSON.parse(fs.readFileSync(temp, "utf8")), key);
    const before = JSON.parse(original.toString("utf8"));
    if (check.refreshToken !== before.refreshToken || check.accessToken !== before.accessToken || check.realmId !== before.realmId) {
      throw new Error("Refusing to migrate tokens");
    }
    fs.renameSync(temp, filePath);
    return "encrypted";
  } catch (error) {
    if (fs.existsSync(temp)) fs.rmSync(temp);
    if (!fs.existsSync(filePath) || !original.equals(fs.readFileSync(filePath))) fs.writeFileSync(filePath, original);
    throw error;
  }
}
