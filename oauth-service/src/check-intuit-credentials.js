import { assessIntuitPair } from "./secret-policy.js";

const result = assessIntuitPair(process.env.QBO_CLIENT_ID, process.env.QBO_CLIENT_SECRET);
if (!result.ok) {
  console.error(result.message);
  process.exit(1);
}
console.log(result.oauthConfigured ? "Intuit credentials accepted." : "Intuit credentials are not set.");
