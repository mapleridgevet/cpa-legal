# cpa-legal

Static pages for CPA, an internal accounting tool of Maple Ridge Mobile Veterinary Services, PLLC. The Privacy Policy and EULA wording is the approved text effective November 6, 2026.

- [Home](index.html)
- [Privacy Policy](privacy-policy.html)
- [EULA](eula.html)
- [Connect or reconnect instructions](connect.html)
- [Disconnect instructions](disconnect.html)

Styles are in `styles.css`. Links are relative so the pages resolve at `/cpa-legal/` on GitHub Pages from the `main` branch, folder `/ (root)`.

`connect.html` and `disconnect.html` are static instructions on this GitHub Pages site. They are not an OAuth redirect URI, and they do not connect, reconnect, or revoke QuickBooks.

`oauth-service/` is a separate Node.js program for owner sign-in, the Intuit redirect, token exchange, and revocation. Jekyll excludes that folder, so GitHub Pages does not publish or run it. It is not deployed. Its README lists the hostname, account, and connector approvals still required. No client secret, token, or accounting data belongs in this repository.
