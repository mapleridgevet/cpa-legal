import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { isForbiddenDataDir, loadConfig } from "../src/config.js";
import { hashOwnerPassword, verifyOwnerPassword } from "../src/password-hash.js";

const serviceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function baseEnv(overrides = {}) {
  return {
    QBO_CLIENT_ID: "client-id",
    QBO_CLIENT_SECRET: "client-secret-value",
    QBO_REDIRECT_URI: "https://mapleridgecpa.com/callback",
    QBO_ENVIRONMENT: "production",
    OWNER_PASSWORD_HASH: hashOwnerPassword("owner-password-value-16"),
    SESSION_SECRET: "session-secret-value-at-least-32-characters",
    PUBLIC_BASE_URL: "https://mapleridgecpa.com",
    DATA_DIR: "/tmp/cpa-oauth-outside-repo",
    ...overrides,
  };
}

test("production configuration fails closed", () => {
  assert.throws(() => loadConfig(baseEnv({ QBO_CLIENT_SECRET: "" })), /both be set or both be absent/);
  assert.throws(() => loadConfig(baseEnv({ QBO_CLIENT_ID: "", QBO_CLIENT_SECRET: "client-secret-value" })), /both be set or both be absent/);
  assert.throws(() => loadConfig(baseEnv({ QBO_CLIENT_ID: "placeholder", QBO_CLIENT_SECRET: "client-secret-value" })), /must not be a placeholder/);
  assert.throws(() => loadConfig(baseEnv({ OWNER_PASSWORD_HASH: "" })), /OWNER_PASSWORD_HASH is missing/);
  assert.throws(() => loadConfig(baseEnv({ OWNER_PASSWORD: "owner-password-value-16" })), /reversible OWNER_PASSWORD is not accepted/);
  const spacedPassword = "  owner-password-value  ";
  const spacedSecret = "  session-secret-value-at-least-32-characters  ";
  const exact = loadConfig(baseEnv({ OWNER_PASSWORD_HASH: hashOwnerPassword(spacedPassword), SESSION_SECRET: spacedSecret }));
  assert.equal(verifyOwnerPassword(spacedPassword, exact.ownerPasswordHash), true);
  assert.equal(verifyOwnerPassword(spacedPassword.trim(), exact.ownerPasswordHash), false);
  assert.equal(exact.sessionSecret, spacedSecret);
  assert.equal(exact.ownerPassword, undefined);
  const setup = loadConfig(baseEnv({ QBO_CLIENT_ID: "", QBO_CLIENT_SECRET: "  " }));
  assert.equal(setup.oauthConfigured, false);
  assert.equal(setup.clientId, "");
  assert.equal(setup.clientSecret, "");
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "http://auth.example.test/callback", PUBLIC_BASE_URL: "http://auth.example.test" })), /production QBO_REDIRECT_URI must use https/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "https://mapleridgevet.github.io/callback", PUBLIC_BASE_URL: "https://mapleridgevet.github.io" })), /GitHub Pages/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "https://auth.example.test/oauth/callback" })), /path must be \/callback/);
  assert.throws(() => loadConfig(baseEnv({ COOKIE_SECURE: "false" })), /COOKIE_SECURE/);
  assert.throws(() => loadConfig(baseEnv({ BIND_HOST: "0.0.0.0" })), /loopback/);
  assert.throws(() => loadConfig(baseEnv({ DATA_DIR: serviceRoot })), /outside the repository/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "https://127.0.0.1/callback", PUBLIC_BASE_URL: "https://127.0.0.1" })), /localhost/);
  const config = loadConfig(baseEnv());
  assert.equal(config.environment, "production");
  assert.equal(config.oauthConfigured, true);
  assert.equal(config.cookieSecure, true);
  assert.equal(config.bindHost, "127.0.0.1");
});

test("preflight accepts setup mode and refuses partial credentials without printing secrets", () => {
  const result = spawnSync(process.execPath, ["src/preflight.js"], {
    cwd: serviceRoot,
    env: { PATH: process.env.PATH },
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Setup configuration is accepted and OAuth is not configured/);
  assert.match(result.stdout, /Partial Intuit credentials were refused/);
  assert.equal(result.stdout.includes("preflight-owner-password"), false);
  assert.equal(result.stderr.includes("preflight-owner-password"), false);
});

test("the credential check does not echo secret values", () => {
  const refused = spawnSync(process.execPath, ["src/check-intuit-credentials.js"], {
    cwd: serviceRoot,
    env: {
      PATH: process.env.PATH,
      QBO_CLIENT_ID: "client-id-value",
      QBO_CLIENT_SECRET: "placeholder",
    },
    encoding: "utf8",
  });
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /QBO_CLIENT_SECRET must not be a placeholder/);
  assert.equal(`${refused.stdout}${refused.stderr}`.includes("client-id-value"), false);

  const accepted = spawnSync(process.execPath, ["src/check-intuit-credentials.js"], {
    cwd: serviceRoot,
    env: {
      PATH: process.env.PATH,
      QBO_CLIENT_ID: "prod-client-id-value",
      QBO_CLIENT_SECRET: "prod-client-secret-value",
    },
    encoding: "utf8",
  });
  assert.equal(accepted.status, 0);
  assert.match(accepted.stdout, /Intuit credentials accepted/);
  assert.equal(`${accepted.stdout}${accepted.stderr}`.includes("prod-client-secret-value"), false);
  assert.equal(`${accepted.stdout}${accepted.stderr}`.includes("prod-client-id-value"), false);
});

test("the process refuses to start when production configuration is incomplete", () => {
  const result = spawnSync(process.execPath, ["src/index.js"], {
    cwd: serviceRoot,
    env: { PATH: process.env.PATH, QBO_ENVIRONMENT: "production" },
    encoding: "utf8",
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Refusing to start/);
  assert.equal(result.stdout.includes("client-secret"), false);
});

test("a Windows data directory outside the program is allowed when there is no git root", () => {
  const pathApi = path.win32;
  const serviceRootWin = "C:\\Users\\naesm\\cpa-oauth-service";
  const dataDir = "C:\\Users\\naesm\\AppData\\Local\\MapleRidge\\cpa-oauth";
  assert.equal(isForbiddenDataDir(dataDir, { serviceRoot: serviceRootWin, gitRoot: null, pathApi }), false);
  assert.equal(isForbiddenDataDir(pathApi.join(serviceRootWin, "data"), { serviceRoot: serviceRootWin, gitRoot: null, pathApi }), true);
  assert.equal(isForbiddenDataDir("C:\\Users\\naesm\\quickbooks-card-connector", {
    serviceRoot: serviceRootWin,
    gitRoot: null,
    pathApi,
  }), false);
});
