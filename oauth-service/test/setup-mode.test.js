import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { hashOwnerPassword } from "../src/password-hash.js";
import { createLoginThrottle } from "../src/login-throttle.js";
import { createFileStateStore, createFileTokenStore, createMemoryStateStore } from "../src/stores.js";

const OWNER_PASSWORD = "owner-password-value-16";
const OWNER_PASSWORD_HASH = hashOwnerPassword(OWNER_PASSWORD);
const REFRESH_TOKEN = "refresh-token-VALUE-should-not-log";
const AUTH_CODE = "auth-code-VALUE-should-not-log";

function setupConfig(overrides = {}) {
  return {
    clientId: "",
    clientSecret: "",
    redirectUri: "https://mapleridgecpa.com/callback",
    environment: "production",
    scope: "com.intuit.quickbooks.accounting",
    ownerPasswordHash: OWNER_PASSWORD_HASH,
    sessionSecret: "session-secret-value-at-least-32-characters",
    publicBaseUrl: "https://mapleridgecpa.com",
    dataDir: fs.mkdtempSync(path.join(os.tmpdir(), "cpa-setup-")),
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
      res.on("end", () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

function cookiePair(setCookie) {
  const first = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return first.split(";")[0];
}

test("setup mode serves sign-in and disconnect without calling Intuit or changing tokens", async () => {
  const config = setupConfig();
  const tokenFile = path.join(config.dataDir, "tokens.json");
  const stateFile = path.join(config.dataDir, "oauth-state.json");
  const tokenStore = createFileTokenStore(tokenFile);
  tokenStore.save({ refreshToken: REFRESH_TOKEN, accessToken: "access-token-VALUE-should-not-log" });
  let calls = 0;
  const app = createApp({
    config,
    stateStore: createFileStateStore(stateFile),
    tokenStore,
    fetchImpl: async () => {
      calls += 1;
      throw new Error("Intuit should not be called");
    },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const health = await request(port, { path: "/health" });
    assert.deepEqual(JSON.parse(health.body), {
      ok: true,
      listening: true,
      mode: "setup",
      oauth: "not-configured",
      quickbooks: "not-connected",
    });
    assert.equal(health.body.includes(REFRESH_TOKEN), false);
    const home = await request(port, { path: "/" });
    assert.equal(home.status, 200);
    assert.match(home.body, /Signing in does not connect QuickBooks/);
    const disconnect = await request(port, { path: "/disconnect" });
    assert.equal(disconnect.status, 200);
    assert.match(disconnect.body, /does not revoke QuickBooks access/);
    assert.match(disconnect.body, /credentials are not configured/);
    const login = await request(port, {
      method: "POST",
      path: "/login",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `password=${encodeURIComponent(OWNER_PASSWORD)}`,
    });
    assert.equal(login.status, 303);
    const cookie = cookiePair(login.headers["set-cookie"]);
    const signedIn = await request(port, { path: "/", headers: { Cookie: cookie } });
    assert.match(signedIn.body, /QuickBooks is not configured/);
    assert.equal(signedIn.body.includes("Connect or reconnect QuickBooks"), false);
    const csrf = signedIn.body.match(/name="csrf" value="([^"]+)"/)[1];
    const connect = await request(port, {
      method: "POST",
      path: "/connect",
      headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded", "X-Forwarded-For": "203.0.113.10", "CF-Connecting-IP": "203.0.113.10" },
      body: `csrf=${encodeURIComponent(csrf)}`,
    });
    assert.equal(connect.status, 409);
    assert.match(connect.body, /No request was sent to Intuit/);
    assert.equal(connect.headers.location, undefined);
    const callback = await request(port, { path: `/callback?code=${AUTH_CODE}&state=not-a-real-state-value` });
    assert.equal(callback.status, 302);
    assert.equal(callback.body, "");
    assert.equal(callback.headers.location.includes(AUTH_CODE), false);
    assert.match(callback.headers["cache-control"], /no-cache, no-store/);
    const revoke = await request(port, {
      method: "POST",
      path: "/disconnect",
      headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: `csrf=${encodeURIComponent(csrf)}`,
    });
    assert.equal(revoke.status, 409);
    assert.match(revoke.body, /Local tokens were not changed/);
    assert.equal(calls, 0);
    assert.equal(fs.existsSync(stateFile), false);
    assert.equal(tokenStore.load().refreshToken, REFRESH_TOKEN);
    const logged = app.log.lines.join("\n");
    assert.equal(logged.includes(OWNER_PASSWORD), false);
    assert.equal(logged.includes(REFRESH_TOKEN), false);
    assert.equal(logged.includes(AUTH_CODE), false);
  } finally {
    server.close();
  }
});

test("failed logins share one throttle across forwarded headers", async () => {
  let now = 10_000;
  const throttle = createLoginThrottle({ now: () => now, maxFailures: 3, windowMs: 60_000 });
  const app = createApp({
    config: setupConfig(),
    now: () => now,
    throttle,
    stateStore: createMemoryStateStore(),
    tokenStore: createFileTokenStore(path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cpa-throttle-app-")), "tokens.json")),
    fetchImpl: async () => {
      throw new Error("Intuit should not be called");
    },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const headers = [
      { "X-Forwarded-For": "203.0.113.1", "CF-Connecting-IP": "203.0.113.1" },
      { "X-Forwarded-For": "203.0.113.2", "X-Real-IP": "198.51.100.2" },
      { Forwarded: "for=203.0.113.3", "CF-Connecting-IP": "203.0.113.9" },
    ];
    for (let i = 0; i < headers.length; i += 1) {
      const failed = await request(port, {
        method: "POST",
        path: "/login",
        headers: { ...headers[i], "Content-Type": "application/x-www-form-urlencoded" },
        body: "password=wrong-password-value",
      });
      assert.equal(failed.status, i === 2 ? 429 : 401);
    }
    const locked = await request(port, {
      method: "POST",
      path: "/login",
      headers: { "X-Forwarded-For": "192.0.2.8", "CF-Connecting-IP": "192.0.2.8", "Content-Type": "application/x-www-form-urlencoded" },
      body: `password=${encodeURIComponent(OWNER_PASSWORD)}`,
    });
    assert.equal(locked.status, 429);
    assert.equal(locked.headers["set-cookie"], undefined);
    assert.match(locked.body, /temporarily unavailable/);
    assert.equal(locked.body.includes(OWNER_PASSWORD), false);
    const stillLocked = await request(port, {
      method: "POST",
      path: "/login",
      headers: { "X-Forwarded-For": "192.0.2.50", "Content-Type": "application/x-www-form-urlencoded" },
      body: `password=${encodeURIComponent(OWNER_PASSWORD)}`,
    });
    assert.equal(stillLocked.status, 429);
    now += 60_000;
    const admitted = await request(port, {
      method: "POST",
      path: "/login",
      headers: { "X-Forwarded-For": "192.0.2.51", "Content-Type": "application/x-www-form-urlencoded" },
      body: `password=${encodeURIComponent(OWNER_PASSWORD)}`,
    });
    assert.equal(admitted.status, 303);
  } finally {
    server.close();
  }
});

test("health reports oauth ready and connected only when a refresh token is stored", async () => {
  const readyDir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-health-ready-"));
  const ready = createApp({
    config: setupConfig({
      clientId: "client-id-value",
      clientSecret: "client-secret-value",
      dataDir: readyDir,
    }),
    stateStore: createMemoryStateStore(),
    tokenStore: createFileTokenStore(path.join(readyDir, "tokens.json")),
    fetchImpl: async () => { throw new Error("Intuit should not be called"); },
  });
  const readyServer = await listen(ready.handler);
  try {
    const body = JSON.parse((await request(readyServer.address().port, { path: "/health" })).body);
    assert.deepEqual(body, {
      ok: true,
      listening: true,
      mode: "oauth",
      oauth: "ready",
      quickbooks: "not-connected",
    });
  } finally {
    readyServer.close();
  }

  const connectedDir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-health-connected-"));
  const tokenStore = createFileTokenStore(path.join(connectedDir, "tokens.json"));
  tokenStore.save({ refreshToken: REFRESH_TOKEN });
  const connected = createApp({
    config: setupConfig({
      clientId: "client-id-value",
      clientSecret: "client-secret-value",
      dataDir: connectedDir,
    }),
    stateStore: createMemoryStateStore(),
    tokenStore,
    fetchImpl: async () => { throw new Error("Intuit should not be called"); },
  });
  const connectedServer = await listen(connected.handler);
  try {
    const response = await request(connectedServer.address().port, { path: "/health" });
    assert.deepEqual(JSON.parse(response.body), {
      ok: true,
      listening: true,
      mode: "oauth",
      oauth: "ready",
      quickbooks: "connected",
    });
    assert.equal(response.body.includes(REFRESH_TOKEN), false);
  } finally {
    connectedServer.close();
  }
});

test("partial Intuit credentials are refused before the app listens", () => {
  assert.throws(() => createApp({
    config: setupConfig({ clientId: "client-id-value", clientSecret: "" }),
    fetchImpl: async () => { throw new Error("Intuit should not be called"); },
  }), /both be set or both be absent/);
});

test("browser sign-in keeps an exact password, including surrounding spaces", async () => {
  const password = "  owner-password-value  ";
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "cpa-browser-login-"));
  const loaded = loadConfig({
    QBO_ENVIRONMENT: "production",
    PUBLIC_BASE_URL: "https://mapleridgecpa.com",
    QBO_REDIRECT_URI: "https://mapleridgecpa.com/callback",
    BIND_HOST: "127.0.0.1",
    PORT: "8787",
    COOKIE_SECURE: "true",
    DATA_DIR: dataDir,
    OWNER_PASSWORD_HASH: hashOwnerPassword(password),
    SESSION_SECRET: "  session-secret-value-at-least-32-characters  ",
  });
  assert.equal(loaded.ownerPasswordHash.includes(password), false);
  assert.equal(loaded.oauthConfigured, false);
  let calls = 0;
  const app = createApp({
    config: { ...loaded, dataDir },
    stateStore: createMemoryStateStore(),
    tokenStore: createFileTokenStore(path.join(dataDir, "qbo-tokens.json")),
    fetchImpl: async () => {
      calls += 1;
      throw new Error("Intuit should not be called");
    },
  });
  const server = await listen(app.handler);
  const port = server.address().port;
  try {
    const home = await request(port, {
      path: "/",
      headers: { Accept: "text/html", "CF-Connecting-IP": "203.0.113.40" },
    });
    assert.equal(home.status, 200);
    const action = home.body.match(/<form method="post" action="([^"]+)">/)[1];
    const field = home.body.match(/<input name="([^"]+)" type="password"/)[1];
    assert.equal(action, "/login");
    assert.equal(field, "password");
    const browserHeaders = {
      "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
      Accept: "text/html,application/xhtml+xml",
      Origin: "https://mapleridgecpa.com",
      Referer: "https://mapleridgecpa.com/",
      "X-Forwarded-For": "203.0.113.40",
      "CF-Connecting-IP": "203.0.113.40",
    };
    const framed = await request(port, {
      method: "POST",
      path: action,
      headers: browserHeaders,
      body: `${encodeURIComponent(field)}=${encodeURIComponent(password)}\r\n`,
    });
    assert.equal(framed.status, 303);
    assert.equal(framed.headers.location, "/");
    const cookie = cookiePair(framed.headers["set-cookie"]);
    assert.match(cookie, /__Host-cpa_session=/);
    const signedIn = await request(port, { path: framed.headers.location, headers: { Cookie: cookie } });
    assert.equal(signedIn.status, 200);
    assert.match(signedIn.body, /QuickBooks is not configured/);
    assert.equal(signedIn.body.includes("Sign in required"), false);

    const trimmed = await request(port, {
      method: "POST",
      path: "/login",
      headers: browserHeaders,
      body: `${field}=${encodeURIComponent(password.trim())}`,
    });
    assert.equal(trimmed.status, 401);
    assert.equal(trimmed.body, "Sign in required");
    assert.equal(trimmed.headers["set-cookie"], undefined);

    const bad = await request(port, {
      method: "POST",
      path: "/login",
      headers: browserHeaders,
      body: `${field}=wrong-password-value`,
    });
    assert.equal(bad.status, 401);
    assert.equal(bad.body, "Sign in required");
    assert.equal(bad.headers.location, undefined);
    assert.equal(bad.headers["set-cookie"], undefined);
    const stillOut = await request(port, { path: "/" });
    assert.match(stillOut.body, /<h1>Owner sign-in<\/h1>/);
    assert.equal(calls, 0);
    assert.equal(app.log.lines.join("\n").includes(password), false);

    const boundary = "cpaBoundary123";
    const multipart = [
      `--${boundary}`,
      `Content-Disposition: form-data; name="${field}"`,
      "",
      password,
      `--${boundary}--`,
      "",
    ].join("\r\n");
    const multi = await request(port, {
      method: "POST",
      path: "/login",
      headers: {
        ...browserHeaders,
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
      },
      body: multipart,
    });
    assert.equal(multi.status, 303);
    assert.match(cookiePair(multi.headers["set-cookie"]), /__Host-cpa_session=/);
  } finally {
    server.close();
  }
});
