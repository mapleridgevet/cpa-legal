# cpa-legal

Static pages for CPA, an internal accounting tool of Maple Ridge Mobile Veterinary Services, PLLC. The Privacy Policy and EULA wording is the approved text effective November 6, 2026.

- [Home](index.html)
- [Privacy Policy](privacy-policy.html)
- [EULA](eula.html)
- [Connect or reconnect instructions](connect.html)
- [Disconnect instructions](disconnect.html)

Styles are in `styles.css`. Links are relative so the pages resolve at `/cpa-legal/` on GitHub Pages from the `main` branch, folder `/ (root)`.

`connect.html` and `disconnect.html` are static instructions. They are not an OAuth redirect URI, and they do not connect, reconnect, or revoke QuickBooks. Production authorization is not configured. The site has no forms, analytics, connector code, credentials, or accounting data.
