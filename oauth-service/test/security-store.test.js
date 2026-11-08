import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createApp, installServer } from "../src/app.js";
import { hashOwnerPassword, planOwnerMigration, verifyOwnerPassword } from "../src/password-hash.js";
import { createMemoryStateStore } from "../src/stores.js";
import { classifyTokenPayload, createProtectedTokenStore, decryptTokenRecord, migrateTokenFile } from "../src/token-crypto.js";
import crypto from "node:crypto";

const OWNER_PASSWORD = "owner-password-value-16";
const SESSION = "session-secret-value-at-least-32-characters";

function appConfig(dir, extra = {}) {
  return {
    clientId: "",
    clientSecret: "",
    redirectUri: "https://mapleridgecpa.com/callback",
    environment: "production",
    scope: "com.intuit.quickbooks.accounting",
    ownerPasswordHash: hashOwnerPassword(OWNER_PASSWORD),
    sessionSecret: SESSION,
    publicBaseUrl: "https://mapleridgecpa.com",
    dataDir: dir,
    cookieSecure: true,
    bindHost: "127.0.0.1",
    port: 0,
    stateTtlMs: 600000,
    sessionTtlMs: 600000,
    tokenKey: null,
    ...extra,
  };
}

function listen(handler) {
  const server = installServer(http.createServer(handler));
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function request(port, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: "127.0.0.1",
      port,
      method: options.method || "GET",
      path: options.path || "/",
      headers: options.headers || {},
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(options.body || "");
  });
}

test("owner migration replaces the reversible password only after the hash verifies", () => {
  const password = "  exact-owner-password  ";
  const record = {
    ownerPassword: password,
    sessionSecret: SESSION,
    clientId: "prod-client-id-value",
    clientSecret: "prod-client-secret-value",
    tokenKey: "kept-token-key",
  };
  const planned = planOwnerMigration(record, password);
  assert.equal(planned.action, "hashed");
  assert.equal(planned.record.ownerPassword, undefined);
  assert.equal(planned.record.sessionSecret, SESSION);
  assert.equal(planned.record.clientId, record.clientId);
  assert.equal(planned.record.clientSecret, record.clientSecret);
  assert.equal(planned.record.tokenKey, record.tokenKey);
  assert.equal(verifyOwnerPassword(password, planned.record.ownerPasswordHash), true);
  assert.equal(verifyOwnerPassword(password.trim(), planned.record.ownerPasswordHash), false);
  assert.equal(JSON.stringify(planned.record).includes(password), false);
  assert.equal(planOwnerMigration(planned.record, password).action, "already-hashed");
});

test("token encryption refuses plaintext and keeps the original when migration fails", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-token-enc-"));
  const file = path.join(dir, "qbo-tokens.json");
  const key = crypto.randomBytes(32);
  const other = crypto.randomBytes(32);
  const record = { accessToken: "access-token-VALUE-should-not-log", refreshToken: "refresh-token-VALUE-should-not-log", realmId: "999000111" };
  const store = createProtectedTokenStore(file, key);
  const locked = createProtectedTokenStore(file, null);
  assert.throws(() => locked.save(record), /encryption key is missing/);
  assert.equal(fs.existsSync(file), false);
  store.save(record);
  const raw = fs.readFileSync(file, "utf8");
  assert.equal(raw.includes(record.refreshToken), false);
  assert.equal(raw.includes(record.accessToken), false);
  assert.equal(raw.includes(record.realmId), false);
  assert.equal(classifyTokenPayload(raw), "encrypted");
  assert.equal(store.load().refreshToken, record.refreshToken);
  assert.throws(() => decryptTokenRecord(JSON.parse(raw), other), /Refusing to read tokens|Unsupported state|unable to authenticate/);
  fs.writeFileSync(file, JSON.stringify(record));
  const broken = path.join(dir, "broken.json");
  fs.writeFileSync(broken, "{");
  assert.throws(() => migrateTokenFile(broken, key), /Refusing to migrate tokens/);
  assert.equal(fs.readFileSync(broken, "utf8"), "{");
  assert.equal(migrateTokenFile(file, key), "encrypted");
  assert.equal(fs.readFileSync(file, "utf8").includes(record.refreshToken), false);
  assert.equal(createProtectedTokenStore(file, key).load().realmId, record.realmId);
  assert.equal(fs.existsSync(`${file}.bak`), false);
  assert.throws(() => createProtectedTokenStore(file, null).load(), /encryption key is missing|Refusing to read tokens/);
});

test("TRACE is not echoed and sensitive pages are not cached", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-trace-"));
  const app = createApp({
    config: appConfig(dir),
    stateStore: createMemoryStateStore(),
    fetchImpl: async () => { throw new Error("Intuit should not be called"); },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const trace = await request(port, { method: "TRACE", path: "/login", body: "password=owner-password-value-16" });
    assert.equal(trace.status, 405);
    assert.equal(trace.body, "");
    assert.equal(trace.body.includes("password"), false);
    assert.equal(trace.headers.allow, "GET, POST");
    const home = await request(port, { path: "/" });
    assert.match(home.headers["cache-control"], /no-cache/);
    assert.match(home.headers["cache-control"], /no-store/);
  } finally {
    server.close();
  }
});
