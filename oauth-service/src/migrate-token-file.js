import fs from "node:fs";
import { migrateTokenFile } from "./token-crypto.js";

const filePath = process.argv[2];
const rawKey = process.env.TOKEN_ENC_KEY || "";
const key = Buffer.from(rawKey, "base64");
if (!filePath) {
  console.error("Token file path is missing");
  process.exit(1);
}
try {
  const result = migrateTokenFile(filePath, key);
  console.log(result);
  if (fs.existsSync(filePath)) {
    const text = fs.readFileSync(filePath, "utf8");
    if (/"refreshToken"\s*:/.test(text) || /"accessToken"\s*:/.test(text) || /"realmId"\s*:/.test(text)) {
      console.error("Refusing to migrate tokens");
      process.exit(1);
    }
  }
} catch {
  console.log("failed");
  process.exit(1);
}
