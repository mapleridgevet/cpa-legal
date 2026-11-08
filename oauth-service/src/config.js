import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isOwnerPasswordHash } from "./password-hash.js";
import { assessIntuitPair } from "./secret-policy.js";

const SERVICE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function isInsideDir(parent, child, pathApi = path) {
  const root = pathApi.resolve(parent);
  const target = pathApi.resolve(child);
  const relative = pathApi.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !pathApi.isAbsolute(relative));
}

export function findGitRoot(start, pathApi = path, exists = fs.existsSync) {
  let current = pathApi.resolve(start);
  while (true) {
    if (exists(pathApi.join(current, ".git"))) return current;
    const parent = pathApi.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

export function isForbiddenDataDir(dataDir, options = {}) {
  const pathApi = options.pathApi || path;
  const serviceRoot = options.serviceRoot || SERVICE_ROOT;
  const gitRoot = options.gitRoot === undefined ? findGitRoot(serviceRoot, pathApi) : options.gitRoot;
  const resolved = pathApi.resolve(dataDir);
  if (isInsideDir(serviceRoot, resolved, pathApi)) return true;
  if (gitRoot && isInsideDir(gitRoot, resolved, pathApi)) return true;
  return false;
}

function required(env, name, problems) {
  const value = env[name];
  if (typeof value !== "string" || value.trim() === "") {
    problems.push(`${name} is missing`);
    return "";
  }
  return value.trim();
}

function requiredSecret(env, name, problems) {
  const value = env[name];
  if (typeof value !== "string" || value.trim() === "") {
    problems.push(`${name} is missing`);
    return "";
  }
  return value;
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
  const intuit = assessIntuitPair(env.QBO_CLIENT_ID, env.QBO_CLIENT_SECRET);
  if (!intuit.ok) problems.push(intuit.message);
  const redirectUri = required(env, "QBO_REDIRECT_URI", problems);
  const reversibleOwner = typeof env.OWNER_PASSWORD === "string" ? env.OWNER_PASSWORD : "";
  const ownerPasswordHash = typeof env.OWNER_PASSWORD_HASH === "string" ? env.OWNER_PASSWORD_HASH : "";
  if (reversibleOwner.trim() !== "") problems.push("reversible OWNER_PASSWORD is not accepted");
  if (!isOwnerPasswordHash(ownerPasswordHash)) problems.push("OWNER_PASSWORD_HASH is missing");
  const sessionSecret = requiredSecret(env, "SESSION_SECRET", problems);
  let tokenKey = null;
  if (typeof env.TOKEN_ENC_KEY === "string" && env.TOKEN_ENC_KEY.trim() !== "") {
    const decoded = Buffer.from(env.TOKEN_ENC_KEY.trim(), "base64");
    if (decoded.length !== 32) problems.push("TOKEN_ENC_KEY is invalid");
    else tokenKey = decoded;
  }
  const publicBaseUrl = required(env, "PUBLIC_BASE_URL", problems);
  const dataDirRaw = required(env, "DATA_DIR", problems);
  const scope = (env.QBO_SCOPE || "com.intuit.quickbooks.accounting").trim();
  const cookieSecure = env.COOKIE_SECURE !== "false";
  const bindHost = (env.BIND_HOST || "127.0.0.1").trim();
  const port = Number(env.PORT || 8787);

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
    if (isForbiddenDataDir(dataDir)) problems.push("DATA_DIR must be outside the repository");
  }

  const production = environment === "production";
  const pinned = JSON.parse(fs.readFileSync(path.join(SERVICE_ROOT, "host-settings.json"), "utf8"));
  if (production) {
    if (pub && pub.origin !== new URL(pinned.publicBaseUrl).origin) {
      problems.push("production PUBLIC_BASE_URL must be https://mapleridgecpa.com");
    }
    if (redirectUri && redirectUri !== pinned.redirectUri) {
      problems.push("production QBO_REDIRECT_URI must be https://mapleridgecpa.com/callback");
    }
    if (bindHost !== pinned.bindHost) problems.push("production BIND_HOST must be 127.0.0.1");
    if (port !== pinned.port) problems.push("production PORT must be 8787");
  }
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
    clientId: intuit.clientId,
    clientSecret: intuit.clientSecret,
    oauthConfigured: intuit.oauthConfigured,
    redirectUri,
    environment,
    scope,
    ownerPasswordHash,
    tokenKey,
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
