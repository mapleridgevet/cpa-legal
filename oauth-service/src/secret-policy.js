export const MIN_INTUIT_CREDENTIAL = 8;

export const PLACEHOLDERS = new Set([
  "placeholder",
  "changeme",
  "your-client-id",
  "your-client-secret",
  "todo",
  "example",
  "none",
  "null",
  "undefined",
  "xxx",
  "test",
  "secret",
  "password",
]);

export function assessIntuitPair(clientId, clientSecret) {
  const id = typeof clientId === "string" ? clientId.trim() : "";
  const secret = typeof clientSecret === "string" ? clientSecret.trim() : "";
  const hasId = id.length > 0;
  const hasSecret = secret.length > 0;
  if (hasId !== hasSecret) {
    return { ok: false, code: "partial", message: "Intuit credentials must both be set or both be absent" };
  }
  if (!hasId) {
    return { ok: true, code: "setup", clientId: "", clientSecret: "", oauthConfigured: false };
  }
  if (id.length < MIN_INTUIT_CREDENTIAL) {
    return { ok: false, code: "short", message: "QBO_CLIENT_ID is too short" };
  }
  if (secret.length < MIN_INTUIT_CREDENTIAL) {
    return { ok: false, code: "short", message: "QBO_CLIENT_SECRET is too short" };
  }
  if (PLACEHOLDERS.has(id.toLowerCase())) {
    return { ok: false, code: "placeholder", message: "QBO_CLIENT_ID must not be a placeholder" };
  }
  if (PLACEHOLDERS.has(secret.toLowerCase())) {
    return { ok: false, code: "placeholder", message: "QBO_CLIENT_SECRET must not be a placeholder" };
  }
  return { ok: true, code: "configured", clientId: id, clientSecret: secret, oauthConfigured: true };
}
