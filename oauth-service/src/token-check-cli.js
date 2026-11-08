import fs from "node:fs";
import { decryptTokenRecord } from "./token-crypto.js";

const filePath = process.argv[2];
const key = Buffer.from(process.env.TOKEN_ENC_KEY || "", "base64");
const expectedRefresh = process.env.CPA_EXPECT_REFRESH || "";
const expectedAccess = process.env.CPA_EXPECT_ACCESS || "";
const expectedRealm = process.env.CPA_EXPECT_REALM || "";
try {
  const record = decryptTokenRecord(JSON.parse(fs.readFileSync(filePath, "utf8")), key);
  const ok = record.refreshToken === expectedRefresh
    && record.accessToken === expectedAccess
    && record.realmId === expectedRealm;
  console.log(ok ? "match" : "nomatch");
  process.exit(ok ? 0 : 1);
} catch {
  console.log("nomatch");
  process.exit(1);
}
