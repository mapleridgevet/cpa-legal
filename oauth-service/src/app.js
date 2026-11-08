import crypto from "node:crypto";
import path from "node:path";
import { openSeal, readCookie, seal, serializeCookie } from "./cookies.js";
import { createLogger } from "./log.js";
import { createFileThrottleStore, createLoginThrottle } from "./login-throttle.js";
import { buildAuthorizeUrl, exchangeCode, revokeToken } from "./oauth.js";
import { verifyOwnerPassword } from "./password-hash.js";
import { parseFormFields } from "./secret-diagnostic.js";
import { assessIntuitPair } from "./secret-policy.js";
import { createFileStateStore, sha256 } from "./stores.js";
import { createProtectedTokenStore } from "./token-crypto.js";

const RESULTS = {
  stored: "Authorization succeeded at Intuit and tokens were stored on this computer. They are not shown. The Windows connector has not been switched to this file.",
  rejected: "Authorization was not accepted. No tokens were stored.",
  access_denied: "QuickBooks did not authorize the connection. No tokens were stored.",
  exchange: "Intuit did not issue tokens. No tokens were stored.",
  missing_code: "The callback did not include an authorization code. No tokens were stored.",
  state: "The callback state did not match an open sign-in. No tokens were stored.",
  reused: "That authorization attempt was already used. No tokens were stored.",
  expired: "That authorization attempt expired. No tokens were stored.",
  session: "The callback did not match the owner session. No tokens were stored.",
  csrf: "The form did not match this session.",
  revoke_ok: "Intuit accepted the revocation request. The local token file was removed. This is not a claim that the QuickBooks Integrations screen was updated.",
  revoke_failed: "Revocation failed. Local tokens were kept. This is not a successful disconnect.",
  no_token: "No local token file was found. Nothing was revoked.",
  signin: "Sign in required.",
  not_configured: "QuickBooks is not configured. No request was sent to Intuit.",
  revoke_not_configured: "Revocation is not configured. No request was sent to Intuit. Local tokens were not changed.",
  unavailable: "QuickBooks is not configured. No authorization code was exchanged.",
  throttled: "Sign-in is temporarily unavailable. Try again later.",
};

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[ch]));
}

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="no-referrer" />
  <title>${escapeHtml(title)}</title>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  ${body}
</body>
</html>`;
}

function send(res, status, headers, body) {
  const payload = Buffer.from(body);
  res.writeHead(status, {
    "Cache-Control": "no-cache, no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Content-Length": payload.length,
    ...headers,
  });
  res.end(payload);
}

function redirect(res, location, extra = {}) {
  send(res, 303, { Location: location, "Content-Type": "text/plain; charset=utf-8", ...extra }, "Redirecting");
}

function redirectSensitive(res, location) {
  res.writeHead(302, {
    Location: location,
    "Cache-Control": "no-cache, no-store",
    "Content-Type": "text/plain; charset=utf-8",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Content-Length": 0,
  });
  res.end();
}

async function readForm(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4096) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  return parseFormFields(Buffer.concat(chunks), req.headers["content-type"]);
}

function passwordsMatch(input, expectedHash) {
  return verifyOwnerPassword(input, expectedHash);
}

function csrfMatch(session, supplied) {
  if (!session || typeof supplied !== "string") return false;
  const a = Buffer.from(session.csrf);
  const b = Buffer.from(supplied);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function quickbooksState(oauthConfigured, tokenStore) {
  if (!oauthConfigured) return "not-connected";
  try {
    const stored = tokenStore.load();
    if (stored && typeof stored.refreshToken === "string" && stored.refreshToken.length > 0) return "connected";
  } catch {
    return "not-connected";
  }
  return "not-connected";
}

export function installServer(server) {
  server.on("clientError", (err, socket) => {
    if (socket.destroyed) return;
    const started = Boolean(socket._httpMessage && socket._httpMessage.headersSent) || socket.bytesWritten > 0;
    if (started) return;
    if (!socket.writable) return;
    socket.end(
      "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, POST\r\nContent-Length: 0\r\nCache-Control: no-cache, no-store\r\nConnection: close\r\n\r\n",
    );
  });
  return server;
}

export function createApp(options) {
  const config = options.config;
  const intuit = assessIntuitPair(config.clientId || "", config.clientSecret || "");
  if (!intuit.ok) throw new Error(`Refusing to start: ${intuit.message}`);
  const oauthConfigured = intuit.oauthConfigured;
  const now = options.now || (() => Date.now());
  const fetchImpl = options.fetchImpl;
  const log = options.log || createLogger();
  if (oauthConfigured) log.noteSecret(intuit.clientSecret);
  log.noteSecret(config.ownerPasswordHash);
  log.noteSecret(config.sessionSecret);
  if (config.tokenKey) log.noteSecret(config.tokenKey.toString("base64"));
  const tokenStore = options.tokenStore || createProtectedTokenStore(path.join(config.dataDir, "qbo-tokens.json"), config.tokenKey);
  const stateStore = options.stateStore || createFileStateStore(path.join(config.dataDir, "oauth-state.json"));
  const throttle = options.throttle || createLoginThrottle({
    now,
    store: createFileThrottleStore(path.join(config.dataDir, "login-throttle.json")),
  });

  function refuseThrottled(res, status) {
    const retryAfter = Math.max(1, Math.ceil(status.retryAfterMs / 1000));
    send(res, 429, {
      "Content-Type": "text/plain; charset=utf-8",
      "Retry-After": String(retryAfter),
    }, RESULTS.throttled);
  }

  function sessionOf(req) {
    return openSeal(readCookie(req, config), config.sessionSecret, now());
  }

  function setSession(res, session) {
    const value = seal(session, config.sessionSecret);
    return serializeCookie(config, value, Math.floor(config.sessionTtlMs / 1000));
  }

  async function handler(req, res) {
    const requestUrl = new URL(req.url, "http://127.0.0.1");
    const pathName = requestUrl.pathname;
    try {
      if (req.method === "TRACE" || req.method === "TRACK") {
        send(res, 405, {
          Allow: "GET, POST",
          "Content-Type": "text/plain; charset=utf-8",
          Connection: "close",
        }, "");
        return;
      }
      if (req.method === "GET" && pathName === "/health") {
        const mode = oauthConfigured ? "oauth" : "setup";
        const body = {
          ok: true,
          listening: true,
          mode,
          oauth: oauthConfigured ? "ready" : "not-configured",
          quickbooks: quickbooksState(oauthConfigured, tokenStore),
        };
        send(res, 200, { "Content-Type": "application/json; charset=utf-8" }, JSON.stringify(body));
        return;
      }
      const session = sessionOf(req);
      if (req.method === "GET" && pathName === "/") {
        send(res, 200, { "Content-Type": "text/html; charset=utf-8" }, session ? controlsHtml(session) : loginHtml());
        return;
      }
      if (req.method === "POST" && pathName === "/login") {
        const gate = throttle.check(now());
        if (gate.locked) {
          log.info("login_throttled", { path: pathName });
          refuseThrottled(res, gate);
          return;
        }
        const form = await readForm(req);
        if (!passwordsMatch(form.get("password") || "", config.ownerPasswordHash)) {
          const failed = throttle.recordFailure(now());
          log.info(failed.locked ? "login_throttled" : "login_failed", { path: pathName });
          if (failed.locked) refuseThrottled(res, failed);
          else send(res, 401, { "Content-Type": "text/plain; charset=utf-8" }, "Sign in required");
          return;
        }
        const admitted = throttle.recordSuccess(now());
        if (admitted.locked) {
          log.info("login_throttled", { path: pathName });
          refuseThrottled(res, admitted);
          return;
        }
        const fresh = {
          sid: crypto.randomBytes(32).toString("base64url"),
          csrf: crypto.randomBytes(32).toString("base64url"),
          exp: now() + config.sessionTtlMs,
        };
        redirect(res, "/", { "Set-Cookie": setSession(res, fresh) });
        return;
      }
      if (req.method === "POST" && pathName === "/connect") {
        if (!session) {
          send(res, 401, { "Content-Type": "text/plain; charset=utf-8" }, "Sign in required");
          return;
        }
        const form = await readForm(req);
        if (!csrfMatch(session, form.get("csrf") || "")) {
          send(res, 403, { "Content-Type": "text/plain; charset=utf-8" }, RESULTS.csrf);
          return;
        }
        if (!oauthConfigured) {
          log.info("connect_unavailable", { path: pathName });
          send(res, 409, { "Content-Type": "text/plain; charset=utf-8" }, RESULTS.not_configured);
          return;
        }
        const state = crypto.randomBytes(32).toString("base64url");
        log.noteSecret(state);
        stateStore.put(sha256(state), { sid: session.sid, exp: now() + config.stateTtlMs, used: false });
        const location = buildAuthorizeUrl({
          clientId: intuit.clientId,
          redirectUri: config.redirectUri,
          scope: config.scope,
          state,
        });
        log.info("authorize_redirect", { path: pathName });
        redirect(res, location);
        return;
      }
      if (req.method === "GET" && pathName === "/callback") {
        if (!oauthConfigured) {
          log.info("callback_unavailable", { path: pathName });
          redirectSensitive(res, "/auth-result?result=rejected&reason=unavailable");
          return;
        }
        const code = requestUrl.searchParams.get("code");
        const state = requestUrl.searchParams.get("state");
        const oauthError = requestUrl.searchParams.get("error");
        if (code) log.noteSecret(code);
        if (state) log.noteSecret(state);
        if (!session) {
          log.info("callback_rejected", { reason: "session" });
          redirectSensitive(res, "/auth-result?result=rejected&reason=session");
          return;
        }
        if (oauthError) {
          log.info("callback_rejected", { reason: "access_denied" });
          redirectSensitive(res, "/auth-result?result=rejected&reason=access_denied");
          return;
        }
        const consumed = stateStore.consume(state, session.sid, now());
        if (!consumed.ok) {
          log.info("callback_rejected", { reason: consumed.reason });
          redirectSensitive(res, `/auth-result?result=rejected&reason=${consumed.reason}`);
          return;
        }
        if (!code) {
          log.info("callback_rejected", { reason: "missing_code" });
          redirectSensitive(res, "/auth-result?result=rejected&reason=missing_code");
          return;
        }
        const exchanged = await exchangeCode({
          clientId: intuit.clientId,
          clientSecret: intuit.clientSecret,
          redirectUri: config.redirectUri,
          code,
          fetchImpl,
        });
        if (!exchanged.ok) {
          log.info("token_exchange_failed", { status: exchanged.status });
          redirectSensitive(res, "/auth-result?result=rejected&reason=exchange");
          return;
        }
        log.noteSecret(exchanged.tokens.access_token);
        log.noteSecret(exchanged.tokens.refresh_token);
        if (typeof exchanged.tokens.realmId === "string") log.noteSecret(exchanged.tokens.realmId);
        const realmId = requestUrl.searchParams.get("realmId");
        if (realmId) log.noteSecret(realmId);
        tokenStore.save({
          accessToken: exchanged.tokens.access_token,
          refreshToken: exchanged.tokens.refresh_token,
          tokenType: exchanged.tokens.token_type || "bearer",
          accessExpiresAt: now() + Number(exchanged.tokens.expires_in || 0) * 1000,
          refreshExpiresAt: now() + Number(exchanged.tokens.x_refresh_token_expires_in || 0) * 1000,
          realmId: realmId || "",
          obtainedAt: now(),
        });
        log.info("tokens_stored", { status: exchanged.status });
        redirectSensitive(res, "/auth-result?result=stored");
        return;
      }
      if (req.method === "GET" && pathName === "/auth-result") {
        const result = requestUrl.searchParams.get("result");
        const reason = requestUrl.searchParams.get("reason") || (result === "stored" ? "stored" : "rejected");
        const key = result === "stored" ? "stored" : RESULTS[reason] ? reason : "rejected";
        const message = RESULTS[key] || RESULTS.rejected;
        send(res, result === "stored" ? 200 : 400, { "Content-Type": "text/html; charset=utf-8" }, page(
          result === "stored" ? "Tokens stored" : "Authorization not accepted",
          `<p>${escapeHtml(message)}</p><p><a href="/">Back</a></p>`,
        ));
        return;
      }
      if (req.method === "GET" && pathName === "/disconnect") {
        const extra = oauthConfigured
          ? ""
          : "<p>QuickBooks credentials are not configured. This page cannot revoke access.</p>";
        send(res, 200, { "Content-Type": "text/html; charset=utf-8" }, page(
          "Disconnect",
          `<p>Opening this address does not revoke QuickBooks access.</p><p><a href="/">Owner sign-in</a> is required before a revocation request is sent.</p>${extra}`,
        ));
        return;
      }
      if (req.method === "POST" && pathName === "/disconnect") {
        if (!session) {
          send(res, 401, { "Content-Type": "text/plain; charset=utf-8" }, "Sign in required");
          return;
        }
        const form = await readForm(req);
        if (!csrfMatch(session, form.get("csrf") || "")) {
          send(res, 403, { "Content-Type": "text/plain; charset=utf-8" }, RESULTS.csrf);
          return;
        }
        if (!oauthConfigured) {
          log.info("revoke_unavailable", { path: pathName });
          send(res, 409, { "Content-Type": "text/plain; charset=utf-8" }, RESULTS.revoke_not_configured);
          return;
        }
        const stored = tokenStore.load();
        if (!stored || typeof stored.refreshToken !== "string" || stored.refreshToken === "") {
          log.info("revoke_skipped", { reason: "no_token" });
          send(res, 409, { "Content-Type": "text/html; charset=utf-8" }, page("Disconnect not completed", `<p>${escapeHtml(RESULTS.no_token)}</p>`));
          return;
        }
        log.noteSecret(stored.refreshToken);
        if (stored.accessToken) log.noteSecret(stored.accessToken);
        let revoked;
        try {
          revoked = await revokeToken({
            clientId: intuit.clientId,
            clientSecret: intuit.clientSecret,
            token: stored.refreshToken,
            fetchImpl,
          });
        } catch {
          revoked = { ok: false, status: 0 };
        }
        if (!revoked.ok) {
          log.info("revoke_failed", { status: revoked.status });
          send(res, 502, { "Content-Type": "text/html; charset=utf-8" }, page("Disconnect not completed", `<p>${escapeHtml(RESULTS.revoke_failed)}</p>`));
          return;
        }
        tokenStore.clear();
        log.info("revoke_succeeded", { status: revoked.status });
        send(res, 200, { "Content-Type": "text/html; charset=utf-8" }, page("Revocation accepted", `<p>${escapeHtml(RESULTS.revoke_ok)}</p>`));
        return;
      }
      send(res, 404, { "Content-Type": "text/plain; charset=utf-8" }, "Not found");
    } catch (error) {
      log.info("request_error", { name: error && error.name ? error.name : "Error" });
      if (!res.headersSent) send(res, 500, { "Content-Type": "text/plain; charset=utf-8" }, "Request failed");
    }
  }

  function loginHtml() {
    return page(
      "Owner sign-in",
      `<p>This is the CPA QuickBooks sign-in for the authorized Owner. It is not the public legal site. Signing in does not connect QuickBooks.</p>
<form method="post" action="/login">
  <label>Owner password <input name="password" type="password" autocomplete="current-password" required /></label>
  <button type="submit">Sign in</button>
</form>`,
    );
  }

  function controlsHtml(session) {
    const csrf = escapeHtml(session.csrf);
    if (!oauthConfigured) {
      return page(
        "Owner signed in",
        `<p>Signed in. QuickBooks is not configured. Connect and revoke are unavailable. Submitting either form does not contact Intuit, does not store an authorization attempt, and does not delete local tokens.</p>
<form method="post" action="/connect">
  <input type="hidden" name="csrf" value="${csrf}" />
  <button type="submit">Connect unavailable</button>
</form>
<form method="post" action="/disconnect">
  <input type="hidden" name="csrf" value="${csrf}" />
  <button type="submit">Revoke unavailable</button>
</form>
<p><a href="/disconnect">Disconnect information</a></p>`,
      );
    }
    return page(
      "QuickBooks authorization",
      `<p>Signed in. Connect sends you to Intuit. Disconnect sends a revocation request only after you submit it. Tokens are not displayed.</p>
<form method="post" action="/connect">
  <input type="hidden" name="csrf" value="${csrf}" />
  <button type="submit">Connect or reconnect QuickBooks</button>
</form>
<form method="post" action="/disconnect">
  <input type="hidden" name="csrf" value="${csrf}" />
  <button type="submit">Revoke QuickBooks tokens</button>
</form>`,
    );
  }

  return { handler, log, tokenStore, stateStore };
}
