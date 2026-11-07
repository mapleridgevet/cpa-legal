import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { isForbiddenDataDir, loadConfig } from "../src/config.js";

const serviceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function baseEnv(overrides = {}) {
  return {
    QBO_CLIENT_ID: "client-id",
    QBO_CLIENT_SECRET: "client-secret-value",
    QBO_REDIRECT_URI: "https://mapleridgecpa.com/callback",
    QBO_ENVIRONMENT: "production",
    OWNER_PASSWORD: "owner-password-value-16",
    SESSION_SECRET: "session-secret-value-at-least-32-characters",
    PUBLIC_BASE_URL: "https://mapleridgecpa.com",
    DATA_DIR: "/tmp/cpa-oauth-outside-repo",
    ...overrides,
  };
}

test("production configuration fails closed", () => {
  assert.throws(() => loadConfig(baseEnv({ QBO_CLIENT_SECRET: "" })), /QBO_CLIENT_SECRET is missing/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "http://auth.example.test/callback", PUBLIC_BASE_URL: "http://auth.example.test" })), /production QBO_REDIRECT_URI must use https/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "https://mapleridgevet.github.io/callback", PUBLIC_BASE_URL: "https://mapleridgevet.github.io" })), /GitHub Pages/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "https://auth.example.test/oauth/callback" })), /path must be \/callback/);
  assert.throws(() => loadConfig(baseEnv({ COOKIE_SECURE: "false" })), /COOKIE_SECURE/);
  assert.throws(() => loadConfig(baseEnv({ BIND_HOST: "0.0.0.0" })), /loopback/);
  assert.throws(() => loadConfig(baseEnv({ DATA_DIR: serviceRoot })), /outside the repository/);
  assert.throws(() => loadConfig(baseEnv({ QBO_REDIRECT_URI: "https://127.0.0.1/callback", PUBLIC_BASE_URL: "https://127.0.0.1" })), /localhost/);
  const config = loadConfig(baseEnv());
  assert.equal(config.environment, "production");
  assert.equal(config.cookieSecure, true);
  assert.equal(config.bindHost, "127.0.0.1");
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
