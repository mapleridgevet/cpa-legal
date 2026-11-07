import fs from "node:fs";
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

let refused = false;
try {
  loadConfig({ QBO_ENVIRONMENT: "production" });
} catch (error) {
  refused = error instanceof Error && error.message.startsWith("Refusing to start");
}
if (!refused) {
  console.error("Refusing health check: empty configuration was accepted");
  process.exit(1);
}

console.log("Health check only. Listener was not started. OAuth was not attempted.");
console.log(`Public URL ${settings.publicBaseUrl}`);
console.log(`Callback ${settings.redirectUri}`);
console.log(`Bind ${settings.bindHost}:${settings.port}`);
console.log(`Tunnel origin ${settings.tunnelOrigin}`);
