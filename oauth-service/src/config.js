import path from "node:path";
import { fileURLToPath } from "node:url";

const SERVICE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = path.resolve(SERVICE_ROOT, "..");

function required(env, name, problems) {
  const value = env[name];
  if (typeof value !== "string" || value.trim() === "") {
    problems.push(`${name} is missing`);
    return "";
  }
  return value.trim();
}

function hostnameOf(value, label, problems) {
  try {
    return new URL(value);
  } catch {
    problems.push(`${label} is not a URL`);
    return null;
  }
}

export function loadConfig(env) {
  const problems = [];
  const environment = required(env, "QBO_ENVIRONMENT", problems);
  if (environment && environment !== "sandbox" && environment !== "production") {
    problems.push("QBO_ENVIRONMENT must be sandbox or production");
  }
  const clientId = required(env, "QBO_CLIENT_ID", problems);
  const clientSecret = required(env, "QBO_CLIENT_SECRET", problems);
  const redirectUri = required(env, "QBO_REDIRECT_URI", problems);
  const ownerPassword = required(env, "OWNER_PASSWORD", problems);
  const sessionSecret = required(env, "SESSION_SECRET", problems);
  const publicBaseUrl = required(env, "PUBLIC_BASE_URL", problems);
  const dataDirRaw = required(env, "DATA_DIR", problems);
  const scope = (env.QBO_SCOPE || "com.intuit.quickbooks.accounting").trim();
  const cookieSecure = env.COOKIE_SECURE !== "false";
  const bindHost = (env.BIND_HOST || "127.0.0.1").trim();
  const port = Number(env.PORT || 8787);

  if (ownerPassword && ownerPassword.length < 16) problems.push("OWNER_PASSWORD must be at least 16 characters");
  if (sessionSecret && sessionSecret.length < 32) problems.push("SESSION_SECRET must be at least 32 characters");
  if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push("PORT is invalid");

  const redirect = redirectUri ? hostnameOf(redirectUri, "QBO_REDIRECT_URI", problems) : null;
  const pub = publicBaseUrl ? hostnameOf(publicBaseUrl, "PUBLIC_BASE_URL", problems) : null;
  if (redirect) {
    if (redirect.username || redirect.password) problems.push("QBO_REDIRECT_URI must not contain credentials");
    if (redirect.search || redirect.hash) problems.push("QBO_REDIRECT_URI must not contain a query or hash");
    if (redirect.pathname !== "/callback") problems.push("QBO_REDIRECT_URI path must be /callback");
  }
  if (redirect && pub && redirect.origin !== pub.origin) {
    problems.push("QBO_REDIRECT_URI origin must match PUBLIC_BASE_URL");
  }

  let dataDir = "";
  if (dataDirRaw) {
    dataDir = path.resolve(dataDirRaw);
    const insideRepo = dataDir === REPO_ROOT || dataDir.startsWith(REPO_ROOT + path.sep);
    if (insideRepo) problems.push("DATA_DIR must be outside the repository");
  }

  const production = environment === "production";
  if (production) {
    if (redirect && redirect.protocol !== "https:") problems.push("production QBO_REDIRECT_URI must use https");
    if (pub && pub.protocol !== "https:") problems.push("production PUBLIC_BASE_URL must use https");
    if (!cookieSecure) problems.push("production COOKIE_SECURE cannot be false");
    if (bindHost !== "127.0.0.1" && bindHost !== "::1") problems.push("production BIND_HOST must be loopback");
    const host = redirect?.hostname || "";
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
      problems.push("production redirect URI must not be localhost");
    }
    if (host === "mapleridgevet.github.io" || host.endsWith(".github.io") || host.endsWith(".githubusercontent.com")) {
      problems.push("redirect host must not be a GitHub Pages host");
    }
  }

  if (problems.length) {
    throw new Error(`Refusing to start: ${problems.join("; ")}`);
  }

  return {
    clientId,
    clientSecret,
    redirectUri,
    environment,
    scope,
    ownerPassword,
    sessionSecret,
    publicBaseUrl: pub.origin,
    dataDir,
    cookieSecure,
    bindHost,
    port,
    stateTtlMs: 10 * 60 * 1000,
    sessionTtlMs: 8 * 60 * 60 * 1000,
  };
}
