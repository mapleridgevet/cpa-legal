import crypto from "node:crypto";

export const SCRYPT_N = 16384;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
const KEYLEN = 32;

function scrypt(password, salt) {
  return crypto.scryptSync(String(password), salt, KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });
}

export function parseOwnerPasswordHash(stored) {
  if (typeof stored !== "string") return null;
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return null;
  if (Number(parts[1]) !== SCRYPT_N || Number(parts[2]) !== SCRYPT_R || Number(parts[3]) !== SCRYPT_P) return null;
  const salt = Buffer.from(parts[4], "base64");
  const hash = Buffer.from(parts[5], "base64");
  if (salt.length !== 16 || hash.length !== KEYLEN) return null;
  return { salt, hash };
}

export function isOwnerPasswordHash(stored) {
  return parseOwnerPasswordHash(stored) !== null;
}

export function hashOwnerPassword(password, salt = crypto.randomBytes(16)) {
  if (typeof password !== "string" || password.length < 16) throw new Error("Owner password is too short");
  if (!Buffer.isBuffer(salt) || salt.length !== 16) throw new Error("Owner password salt is invalid");
  const hash = scrypt(password, salt);
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export function verifyOwnerPassword(password, stored) {
  const parsed = parseOwnerPasswordHash(stored);
  const salt = parsed ? parsed.salt : Buffer.alloc(16, 7);
  let actual;
  try {
    actual = scrypt(password, salt);
  } catch {
    return false;
  }
  if (!parsed || actual.length !== parsed.hash.length) return false;
  return crypto.timingSafeEqual(actual, parsed.hash);
}

export function planOwnerMigration(record, password) {
  if (!record || typeof record !== "object") throw new Error("Owner record is missing");
  if (record.ownerPasswordHash && !record.ownerPassword) {
    if (!isOwnerPasswordHash(record.ownerPasswordHash)) throw new Error("Owner password hash is invalid");
    return { action: "already-hashed", record: { ...record } };
  }
  if (typeof password !== "string" || password.length < 16) throw new Error("Owner password is too short");
  const ownerPasswordHash = hashOwnerPassword(password);
  if (!verifyOwnerPassword(password, ownerPasswordHash)) throw new Error("Owner password hash did not verify");
  const next = { ...record, ownerPasswordHash };
  delete next.ownerPassword;
  return { action: "hashed", record: next };
}
