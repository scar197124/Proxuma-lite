# Proxuma Lite Main — Stable GitHub Release

Proxuma Lite is a privacy-first offline link scanner that analyzes suspicious URLs locally in the browser.

## Stable Lite rules
- Lite is the fast gateway layer.
- QR scanner stays in Lite.
- Output stays simple: risk score, primary concern, findings, suggestions.
- No deep Shield-only panels.
- No Sense-style long explanations.

## Features
- Main UI / glass product layout
- Local risk engine powered by `proxuma.security.js`
- Risk score and explainable findings
- QR scanner using the browser and `html5-qrcode`
- Light / dark theme toggle
- GitHub Pages-ready root structure

## Test locally
Open `index.html` in a browser and test:

```text
https://secure-login-paypal.ru/account-verify?redirect=aHR0cHM6Ly9ldmlsLmNvbQ==
```

## Deploy on GitHub Pages
Upload all root files to your repository, then enable Pages from `main / root`.

## Privacy
No link is uploaded by the scanner. Analysis runs locally in the browser. QR camera access, when used, stays inside the browser tab.
