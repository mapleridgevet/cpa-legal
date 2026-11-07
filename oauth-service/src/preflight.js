import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadConfig } from "./config.js";

const settings = JSON.parse(fs.readFileSync(new URL("../host-settings.json", import.meta.url), "utf8"));
const expected = {
  publicBaseUrl: "https://mapleridgecpa.com",
  redirectUri: "https://mapleridgecpa.com/callback",
  bindHost: "127.0.0.1",
  port: 8787,
  tunnelOrigin: "http://127.0.0.1:8787",
};
for (const [key, value] of Object.entries(expected)) {
  if (settings[key] !== value) {
    console.error(`Refusing health check: host-settings ${key} is not the approved value`);
    process.exit(1);
  }
}

function productionEnv(extra = {}) {
  return {
    QBO_ENVIRONMENT: "production",
    PUBLIC_BASE_URL: settings.publicBaseUrl,
    QBO_REDIRECT_URI: settings.redirectUri,
    BIND_HOST: settings.bindHost,
    PORT: String(settings.port),
    COOKIE_SECURE: "true",
    DATA_DIR: path.join(os.tmpdir(), "cpa-oauth-preflight"),
    OWNER_PASSWORD: "preflight-owner-password",
    SESSION_SECRET: "preflight-session-secret-32chars-min",
    ...extra,
  };
}

let emptyRefused = false;
try {
  loadConfig({ QBO_ENVIRONMENT: "production" });
} catch (error) {
  emptyRefused = error instanceof Error && error.message.startsWith("Refusing to start");
}
if (!emptyRefused) {
  console.error("Refusing health check: empty configuration was accepted");
  process.exit(1);
}

let setup;
try {
  setup = loadConfig(productionEnv());
} catch {
  console.error("Refusing health check: setup configuration was rejected");
  process.exit(1);
}
if (setup.oauthConfigured !== false || setup.clientId !== "" || setup.clientSecret !== "") {
  console.error("Refusing health check: setup configuration enabled OAuth");
  process.exit(1);
}

let partialRefused = false;
try {
  loadConfig(productionEnv({ QBO_CLIENT_ID: "client-id-value" }));
} catch (error) {
  partialRefused = error instanceof Error && error.message.includes("both be set or both be absent");
}
if (!partialRefused) {
  console.error("Refusing health check: partial Intuit credentials were accepted");
  process.exit(1);
}

console.log("Health check only. Listener was not started. OAuth was not attempted.");
console.log("Empty production configuration was refused.");
console.log("Setup configuration is accepted and OAuth is not configured.");
console.log("Partial Intuit credentials were refused.");
console.log(`Public URL ${settings.publicBaseUrl}`);
console.log(`Callback ${settings.redirectUri}`);
console.log(`Bind ${settings.bindHost}:${settings.port}`);
console.log(`Tunnel origin ${settings.tunnelOrigin}`);
