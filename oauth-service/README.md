# CPA OAuth service

Owner-only QuickBooks Online sign-in, connect/reconnect, callback, and revoke program for one internal company. It is not the public legal site and GitHub Pages does not run it.

Nothing in this folder is a live Intuit connection. No client secret, token, realm ID, or accounting data is committed. Starting it requires environment values the Owner supplies later, on the Company PC, outside this repository.

## What it does

After configuration, the process listens on `127.0.0.1` only.

- `GET /` is the sign-in page. The Owner password comes from `OWNER_PASSWORD`. A wrong password returns 401 and does not set a session.
- After sign-in, **Connect or reconnect QuickBooks** creates a single-use `state` bound to that session, expiring in 10 minutes, and redirects only to `https://appcenter.intuit.com/connect/oauth2`.
- `GET /callback` accepts the authorization code only when the state matches that session, is unused, and is unexpired. It then exchanges the code at Intuit’s token endpoint with the client secret. Tokens are written to a file under `DATA_DIR` with mode `0600` and are not returned in the browser or by any download route.
- **Revoke QuickBooks tokens** calls `POST https://developer.api.intuit.com/v2/oauth2/tokens/revoke`. HTTP 200 clears the local file. Any other result, including a thrown network error, keeps the file and says the disconnect was not successful.
- `GET /disconnect` does not revoke anything. It is safe for Intuit to land a browser there.

The service refuses to start in production unless the redirect URI is `https` on the same origin as `PUBLIC_BASE_URL`, the path is `/callback`, the host is not localhost and not a `github.io` host, cookies are `Secure`, the bind address is loopback, and `DATA_DIR` is outside this repository.

## Run the tests

From this directory, with Node.js 20 or newer:

```sh
npm test
```

There are no runtime dependencies. Tests use a fake Intuit HTTP client. They do not authorize or revoke a real company.

## Deployment that keeps tokens on the Company PC

Intuit production redirect URIs must be HTTPS and cannot be an IP address or a GitHub Pages host. This repository’s Pages site stays `https://mapleridgevet.github.io/cpa-legal/` for legal and instruction HTML only.

Verified free front door: [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/) on Cloudflare’s free plan. Cloudflare’s current docs require a Cloudflare account and a domain whose DNS Cloudflare can publish. A quick tunnel hostname on `trycloudflare.com` changes when the process restarts, so it is not a redirect URI to register with Intuit.

Recommended shape, after the Owner approves it:

1. Create a free Cloudflare account. Add a domain the Company already controls, or approve buying and delegating one. A subdomain such as `qbo-auth.example.com` is enough. Do not point `mapleridgevet.github.io` at this service.
2. On the same Windows PC as the connector, install `cloudflared` and a named tunnel to `http://127.0.0.1:8787`. Cloudflare presents the public HTTPS certificate. The Node process does not need a public inbound port.
3. Choose `DATA_DIR` outside the git checkout, readable only by the Owner Windows account.
4. Set `QBO_CLIENT_ID`, `QBO_CLIENT_SECRET`, `OWNER_PASSWORD` (16+ characters), `SESSION_SECRET` (32+ characters), `PUBLIC_BASE_URL`, and `QBO_REDIRECT_URI` to `https://THAT-HOST/callback`. Keep those in the user environment, not in git.
5. In the Intuit developer portal, register that exact redirect URI on the Production redirect list when ready. Set Launch URL and Connect/Reconnect URL to `https://THAT-HOST/`. The legal homepage is not a sign-in page. The Disconnect URL can remain `https://mapleridgevet.github.io/cpa-legal/disconnect.html` or be `https://THAT-HOST/disconnect`. Neither address revokes tokens by being opened.
6. Start `npm start` only when those values exist. This repository does not start it.

Tradeoff: Cloudflare terminates TLS, so the authorization code in the callback URL and the token-exchange body pass through Cloudflare. A tunnel also stops when the PC or `cloudflared` stops. A paid VM with its own certificate would avoid Cloudflare seeing the code, but this work does not buy hosting. A free remote app host that stores the token file on someone else’s disk would be a worse match for an internal company file and is not recommended.

## Connector gap

`authorize-quickbooks.ps1` on the Company PC is unchanged. Its sandbox callback remains `http://localhost:8000/callback`. This service does not read that script, does not write its token file, and does not publish a token download API.

The service writes `DATA_DIR/qbo-tokens.json` with `accessToken`, `refreshToken`, `tokenType`, `accessExpiresAt`, `refreshExpiresAt`, `realmId`, and `obtainedAt`. Whether the PowerShell connector can read that shape is unknown. Until the Owner approves a connector change, or confirms the non-secret field names and path, CPA’s existing launcher will not use tokens stored here. Do not email the file or copy it into the repository.

## Proposed privacy and EULA edits

Not applied. The November 6, 2026 Privacy Policy and EULA are unchanged.

If this service is later run on the Company PC behind a tunnel, the public policy should be updated, in a separate approval, to say:

- GitHub Pages still serves only static legal and instruction pages. It is not the OAuth redirect URI.
- Production authorization uses a separate HTTPS callback. The sandbox localhost callback remains only for the current development connector until cutover.
- The authorization code and company ID can appear briefly on that callback URL. The service exchanges the code and stores tokens in a local file on the Company PC, not in a GitHub repository and not in a hosted database.
- If a tunnel provider terminates HTTPS, that provider can see the callback request and the token exchange.
- The client secret stays in the PC environment.
- Revocation is an authenticated request from that service, plus the QuickBooks Integrations disconnect. Opening the public disconnect page does not revoke tokens.

Do not describe the service as live, and do not submit these URLs to Intuit, until the hostname and connector handoff are approved.
