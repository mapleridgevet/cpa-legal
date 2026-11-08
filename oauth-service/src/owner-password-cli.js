import { hashOwnerPassword, verifyOwnerPassword } from "./password-hash.js";

const mode = process.argv[2];
const password = process.env.OWNER_PASSWORD;
const stored = process.env.OWNER_PASSWORD_HASH;

if (mode === "hash") {
  if (typeof password !== "string" || password.length < 16) {
    console.error("Owner password is too short");
    process.exit(1);
  }
  process.stdout.write(hashOwnerPassword(password));
  process.exit(0);
}

if (mode === "verify") {
  const ok = verifyOwnerPassword(typeof password === "string" ? password : "", typeof stored === "string" ? stored : "");
  console.log(ok ? "match" : "nomatch");
  process.exit(ok ? 0 : 1);
}

console.error("Usage: node src/owner-password-cli.js hash|verify");
process.exit(1);
