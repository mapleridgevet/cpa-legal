import http from "node:http";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

let config;
try {
  config = loadConfig(process.env);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Refusing to start");
  process.exit(1);
}

const app = createApp({ config, fetchImpl: globalThis.fetch });
const server = http.createServer(app.handler);
server.listen(config.port, config.bindHost, () => {
  const mode = config.oauthConfigured ? "oauth" : "setup";
  console.error(`cpa-oauth-service listening on ${config.bindHost}:${config.port} mode=${mode}`);
});
