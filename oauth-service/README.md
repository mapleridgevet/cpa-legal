# CPA OAuth service

Owner-only QuickBooks Online sign-in, connect/reconnect, callback, and revoke program for one internal company. It is not the public legal site and GitHub Pages does not run it.

Nothing in this folder is a live Intuit connection. No client secret, token, realm ID, or accounting data is committed. Starting it requires environment values the Owner supplies later, on the Company PC, outside this repository.

## What it does

After configuration, the process listens on `127.0.0.1` only.

- `GET /` is the sign-in page. The Owner password comes from `OWNER_PASSWORD` and is compared exactly, including any spaces at either end. A wrong password returns plain text `Sign in required` and does not set a session. Five failures in 15 minutes lock sign-in for the rest of that window. The lock is one process-wide bucket. `X-Forwarded-For`, `CF-Connecting-IP`, and similar headers do not create a new bucket.
- Before Intuit production keys exist, the process can listen in setup mode. `GET /` and `GET /disconnect` work. Connect, callback, and revoke do not call Intuit, do not store an authorization attempt, and do not delete a token file. Health says `mode` is `setup`, `oauth` is `not-configured`, and `quickbooks` is `not-connected`.
- After both production keys are saved, **Connect or reconnect QuickBooks** creates a single-use `state` bound to that session, expiring in 10 minutes, and redirects only to `https://appcenter.intuit.com/connect/oauth2`. Health then says `oauth` is `ready`. `quickbooks` is `connected` only when a local refresh token is stored. One key without the other refuses to start. Placeholder values are refused.
- `GET /callback` accepts the authorization code only when the state matches that session, is unused, and is unexpired. It then exchanges the code at Intuit’s token endpoint with the client secret. Tokens are written to a file under `DATA_DIR` with mode `0600` and are not returned in the browser or by any download route.
- **Revoke QuickBooks tokens** calls `POST https://developer.api.intuit.com/v2/oauth2/tokens/revoke`. HTTP 200 clears the local file. Any other result, including a thrown network error, keeps the file and says the disconnect was not successful.
- `GET /disconnect` does not revoke anything. It is safe for Intuit to land a browser there.

The service refuses to start in production unless the public URL is `https://mapleridgecpa.com`, the redirect URI is exactly `https://mapleridgecpa.com/callback`, cookies are `Secure`, the bind address is `127.0.0.1`, the port is `8787`, and `DATA_DIR` is outside this program directory and outside any git checkout. On Windows, token files get a discretionary ACL only: inheritance disabled and one Allow entry for the current user. The code uses `GetAccessControl(Access)` and `SetAccessControl`, not `Set-Acl`, because `Set-Acl` also writes the audit list and demands `SeSecurityPrivilege`. The write is deleted if that DACL cannot be set or read back. Node’s Unix mode bits stay `0666` on Windows, so those tests read the DACL there and still require mode `0600` on Linux.

## Run the tests

From this directory, with Node.js 20 or newer:

```sh
npm test
```

There are no runtime dependencies. Tests use a fake Intuit HTTP client. They do not authorize or revoke a real company.

## Deployment that keeps tokens on the Company PC

Intuit production redirect URIs must be HTTPS and cannot be an IP address or a GitHub Pages host. This repository’s Pages site stays `https://mapleridgevet.github.io/cpa-legal/` for legal and instruction HTML only.

Verified free front door: [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/) on Cloudflare’s free plan. Cloudflare’s current docs require a Cloudflare account and a domain whose DNS Cloudflare can publish. A quick tunnel hostname on `trycloudflare.com` changes when the process restarts, so it is not a redirect URI to register with Intuit.

The domain `mapleridgecpa.com` is active at Cloudflare. The Owner added the named tunnel `mapleridge-cpa` and published `mapleridgecpa.com` to `http://127.0.0.1:8787`. This repository does not change Cloudflare.

`install.ps1` copies the program to `C:\Users\naesm\cpa-oauth-service` and writes non-secret settings under `C:\Users\naesm\AppData\Local\MapleRidge\cpa-oauth`. It does not write into `C:\Users\naesm\quickbooks-card-connector`. With no switch it runs the tests and the secret-free health check, then stops. It does not listen and does not contact Intuit.

`-ConfigureOwner` prompts, with hidden input, for the owner password (16+) and session secret (32+) and stores them in a DPAPI file for the current Windows user. It does not ask for Intuit keys and does not start the listener. `-ConfigureIntuit` prompts for the production client id and secret together, refuses a placeholder or a single value, and replaces the secret file only after both are accepted. The owner password, session secret, `service-config.json`, and token files stay in place. The listener still does not start.

`start-oauth-service.ps1` is the only script that listens. Without owner secrets it exits. With owner secrets and no Intuit keys it listens in setup mode. With both Intuit keys it enables OAuth. With only one Intuit key it exits. Starting it is what makes `https://mapleridgecpa.com/` answer, because the tunnel route is already published. Do not start it until that publication is intended. Intuit has not been asked to accept the setup-only pages.

Tradeoff: Cloudflare terminates TLS, so the owner password, and later the authorization code and token-exchange body, pass through Cloudflare. A tunnel also stops when the PC or `cloudflared` stops. A paid VM with its own certificate would avoid Cloudflare seeing the code, but this work does not buy hosting. A free remote app host that stores the token file on someone else’s disk would be a worse match for an internal company file and is not recommended.

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
