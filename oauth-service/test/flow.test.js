import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createApp } from "../src/app.js";
import { createFileTokenStore, createMemoryStateStore } from "../src/stores.js";

const CLIENT_SECRET = "test-client-secret-value-not-real";
const ACCESS_TOKEN = "access-token-VALUE-should-not-log";
const REFRESH_TOKEN = "refresh-token-VALUE-should-not-log";
const AUTH_CODE = "auth-code-VALUE-should-not-log";
const OWNER_PASSWORD = "owner-password-value-16";

function testConfig(overrides = {}) {
  return {
    clientId: "client-id-value",
    clientSecret: CLIENT_SECRET,
    redirectUri: "https://auth.example.test/callback",
    environment: "sandbox",
    scope: "com.intuit.quickbooks.accounting",
    ownerPassword: OWNER_PASSWORD,
    sessionSecret: "session-secret-value-at-least-32-characters",
    publicBaseUrl: "https://auth.example.test",
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), "cpa-oauth-")),
    cookieSecure: true,
    bindHost: "127.0.0.1",
    port: 0,
    stateTtlMs: 10 * 60 * 1000,
    sessionTtlMs: 8 * 60 * 60 * 1000,
    ...overrides,
  };
}

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function request(port, { method = "GET", path: reqPath = "/", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, method, path: reqPath, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}

function cookiePair(setCookie) {
  const first = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return first.split(";")[0];
}

async function signIn(port) {
  const login = await request(port, {
    method: "POST",
    path: "/login",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `password=${encodeURIComponent(OWNER_PASSWORD)}`,
  });
  assert.equal(login.status, 303);
  const cookie = cookiePair(login.headers["set-cookie"]);
  const home = await request(port, { path: "/", headers: { Cookie: cookie } });
  const csrf = home.body.match(/name="csrf" value="([^"]+)"/)[1];
  return { cookie, csrf, login };
}

test("unauthenticated connect and disconnect are denied and do not call Intuit", async () => {
  let calls = 0;
  const app = createApp({
    config: testConfig(),
    stateStore: createMemoryStateStore(),
    tokenStore: createFileTokenStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cpa-tokens-")), "tokens.json")),
    fetchImpl: async () => {
      calls += 1;
      throw new Error("Intuit should not be called");
    },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const connect = await request(port, { method: "POST", path: "/connect", body: "csrf=nope" });
    const disconnect = await request(port, { method: "POST", path: "/disconnect", body: "csrf=nope" });
    assert.equal(connect.status, 401);
    assert.equal(connect.body, "Sign in required");
    assert.equal(connect.headers.location, undefined);
    assert.equal(disconnect.status, 401);
    assert.equal(calls, 0);
  } finally {
    server.close();
  }
});

test("callback rejects unknown, reused, expired, and cross-session state", async () => {
  const calls = [];
  const config = testConfig();
  let now = 1_700_000_000_000;
  const app = createApp({
    config,
    now: () => now,
    stateStore: createMemoryStateStore(),
    tokenStore: createFileTokenStore(path.join(config.dataDir, "tokens.json")),
    fetchImpl: async () => {
      calls.push("fetch");
      return { ok: true, status: 200, async json() { return { access_token: ACCESS_TOKEN, refresh_token: REFRESH_TOKEN, expires_in: 3600 }; } };
    },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const owner = await signIn(port);
    const other = await signIn(port);
    const started = await request(port, {
      method: "POST",
      path: "/connect?next=https://evil.example/phish",
      headers: { Cookie: owner.cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: `csrf=${encodeURIComponent(owner.csrf)}&redirect=https://evil.example/phish`,
    });
    assert.equal(started.status, 303);
    const location = new URL(started.headers.location);
    assert.equal(location.origin, "https://appcenter.intuit.com");
    assert.equal(location.pathname, "/connect/oauth2");
    assert.equal(started.headers.location.includes("evil.example"), false);
    assert.equal(started.headers.location.includes(CLIENT_SECRET), false);
    const state = location.searchParams.get("state");

    const unknown = await request(port, {
      path: `/callback?code=${AUTH_CODE}&state=not-the-issued-state-value`,
      headers: { Cookie: owner.cookie },
    });
    assert.equal(unknown.status, 303);
    assert.match(unknown.headers.location, /reason=state/);
    assert.equal(calls.length, 0);

    now += config.stateTtlMs + 1;
    const expired = await request(port, {
      path: `/callback?code=${AUTH_CODE}&state=${encodeURIComponent(state)}`,
      headers: { Cookie: owner.cookie },
    });
    assert.match(expired.headers.location, /reason=expired/);
    assert.equal(calls.length, 0);
    now -= config.stateTtlMs + 1;

    const wrongSession = await request(port, {
      path: `/callback?code=${AUTH_CODE}&state=${encodeURIComponent(state)}`,
      headers: { Cookie: other.cookie },
    });
    assert.match(wrongSession.headers.location, /reason=session/);
    assert.equal(calls.length, 0);

    const ok = await request(port, {
      path: `/callback?code=${AUTH_CODE}&state=${encodeURIComponent(state)}&realmId=999000111`,
      headers: { Cookie: owner.cookie },
    });
    assert.match(ok.headers.location, /result=stored/);
    assert.equal(ok.body.includes(ACCESS_TOKEN), false);
    const shown = await request(port, { path: ok.headers.location, headers: { Cookie: owner.cookie } });
    assert.equal(shown.status, 200);
    assert.equal(shown.body.includes(ACCESS_TOKEN), false);
    assert.equal(shown.body.includes(REFRESH_TOKEN), false);
    assert.equal(shown.body.includes("999000111"), false);
    assert.equal(calls.length, 1);

    const reused = await request(port, {
      path: `/callback?code=${AUTH_CODE}&state=${encodeURIComponent(state)}`,
      headers: { Cookie: owner.cookie },
    });
    assert.match(reused.headers.location, /reason=reused/);
    assert.equal(calls.length, 1);

    const logged = app.log.lines.join("\n");
    for (const secret of [CLIENT_SECRET, ACCESS_TOKEN, REFRESH_TOKEN, AUTH_CODE, OWNER_PASSWORD, "999000111"]) {
      assert.equal(logged.includes(secret), false, secret);
    }
    const hidden = await request(port, { path: "/tokens" });
    assert.equal(hidden.status, 404);
    assert.equal(hidden.body.includes(ACCESS_TOKEN), false);
  } finally {
    server.close();
  }
});

test("revoke errors do not report success and do not delete tokens", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-revoke-"));
  const tokenStore = createFileTokenStore(path.join(dir, "tokens.json"));
  tokenStore.save({ accessToken: ACCESS_TOKEN, refreshToken: REFRESH_TOKEN, realmId: "999000111" });
  const statuses = [400, 500];
  let index = 0;
  const app = createApp({
    config: testConfig(),
    stateStore: createMemoryStateStore(),
    tokenStore,
    fetchImpl: async () => {
      const status = statuses[Math.min(index, statuses.length - 1)];
      index += 1;
      if (status === 500) throw new Error(`network ${REFRESH_TOKEN}`);
      return { ok: false, status, async json() { return { token: REFRESH_TOKEN }; } };
    },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const owner = await signIn(port);
    const denied = await request(port, {
      method: "POST",
      path: "/disconnect",
      headers: { Cookie: owner.cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: `csrf=${encodeURIComponent(owner.csrf)}`,
    });
    assert.equal(denied.status, 502);
    assert.match(denied.body, /not a successful disconnect/);
    assert.equal(denied.body.includes("Intuit accepted the revocation"), false);
    assert.equal(tokenStore.load().refreshToken, REFRESH_TOKEN);

    const thrown = await request(port, {
      method: "POST",
      path: "/disconnect",
      headers: { Cookie: owner.cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: `csrf=${encodeURIComponent(owner.csrf)}`,
    });
    assert.equal(thrown.status, 502);
    assert.match(thrown.body, /not a successful disconnect/);
    assert.equal(tokenStore.load().refreshToken, REFRESH_TOKEN);
    assert.equal(app.log.lines.join("\n").includes(REFRESH_TOKEN), false);
  } finally {
    server.close();
  }
});

test("accepted revoke removes the token file and a wrong csrf does not", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-revoke-ok-"));
  const tokenStore = createFileTokenStore(path.join(dir, "tokens.json"));
  tokenStore.save({ accessToken: ACCESS_TOKEN, refreshToken: REFRESH_TOKEN });
  const mode = fs.statSync(tokenStore.filePath).mode & 0o777;
  assert.equal(mode, 0o600);
  const app = createApp({
    config: testConfig(),
    stateStore: createMemoryStateStore(),
    tokenStore,
    fetchImpl: async () => ({ ok: true, status: 200, async json() { return {}; } }),
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const owner = await signIn(port);
    assert.match(owner.login.headers["set-cookie"][0], /__Host-cpa_session=/);
    assert.match(owner.login.headers["set-cookie"][0], /HttpOnly/);
    assert.match(owner.login.headers["set-cookie"][0], /SameSite=Lax/);
    assert.match(owner.login.headers["set-cookie"][0], /Secure/);
    const csrf = await request(port, {
      method: "POST",
      path: "/disconnect",
      headers: { Cookie: owner.cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: "csrf=wrong-csrf-value",
    });
    assert.equal(csrf.status, 403);
    assert.equal(tokenStore.load().refreshToken, REFRESH_TOKEN);
    const ok = await request(port, {
      method: "POST",
      path: "/disconnect",
      headers: { Cookie: owner.cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: `csrf=${encodeURIComponent(owner.csrf)}`,
    });
    assert.equal(ok.status, 200);
    assert.match(ok.body, /Intuit accepted the revocation request/);
    assert.equal(tokenStore.load(), null);
  } finally {
    server.close();
  }
});
