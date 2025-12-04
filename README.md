# Proxuma Lite – Offline Link Intelligence

Proxuma Lite is a **privacy-first URL and QR analysis tool**. It runs entirely in your browser, with **no servers, no tracking, and no cloud dependencies**. Every scan is performed locally using the Proxuma Security Engine, a heuristic risk model designed to help you understand how risky a link might be *before* you open it.

> No accounts. No history. No network calls. Everything stays on your device.

---

## Key Features

- 🔐 **Heuristic Risk Scoring (0–100)**  
  Multi-factor risk scoring based on protocol, domain structure, path behavior, redirects, and encoding.

- 🧠 **Phishing & Scam Detection Signals**  
  Identifies patterns commonly found in phishing pages, credential harvesting flows, fake login portals, and prize/lottery scams.

- 🧬 **Brand Impersonation & Look-alike Domains**  
  Flags punycode, homograph tricks, mixed alphabets, and domains that visually resemble major brands.

- 🧩 **Redirect & Shortener Awareness**  
  Detects redirect parameters, hidden destinations, URL shorteners, and attempts to conceal the final landing page.

- 🧾 **Structured Findings + Human-Readable Verdict**  
  Every scan produces a summary, verdict, detailed findings, and suggestions written in plain language.

- 📷 **Local QR Scanner (Browser-Native)**  
  Uses the browser’s `BarcodeDetector` API (where supported) to decode QR codes locally. You can scan via camera or upload a QR image, then analyze the decoded URL with the same engine.

- 🌓 **Light / Dark Neon UI**  
  Clean, responsive layout designed for both desktop and mobile, with a neon-accent dark mode and a neutral light mode.

---

## Engine Overview

The **Proxuma Security Engine – Heuristic v10** performs structural and behavioral analysis of a URL, including:

- Protocol checks (`http`, `https`, and non-standard schemes)  
- Domain and TLD heuristics, including suspicious TLDs and bare IPs  
- Punycode, non-ASCII, and mixed Latin/Cyrillic detection  
- Login, payment, and verification keyword detection in paths and queries  
- Dangerous file extensions and double-extension patterns (e.g. `.pdf.exe`)  
- Percent-encoding and obfuscation density  
- Redirect parameters and base64-encoded redirect targets  
- Entropy analysis for auto-generated or random-looking URLs  
- Clustered threat signals (phishing, malware delivery, redirect cloaking, etc.)

The engine does **not** execute any remote code or external network lookups. All analysis is done through static inspection of the URL string.

---

## AI-Assisted Validation

To help ensure the engine behaves consistently and safely, Proxuma Lite has been evaluated using **independent AI-based analysis models**. These models were used to:

- Cross-check that the engine’s logic is **non-malicious and self-contained**  
- Validate that **no external network calls** are made during scanning  
- Stress-test a wide range of benign and malicious URLs to verify that risk scores and verdicts behave in a **stable, explainable way**

This AI-assisted validation is not a formal certification, but it is an additional layer of assurance that:

- The engine is focused on **defensive analysis only**  
- The risk model stays within **clear, documented safety boundaries**  
- The tool is suitable for offline, privacy-respecting use

---

## Privacy & Data Handling

Proxuma Lite is designed with a strict privacy posture:

- ❌ No accounts  
- ❌ No telemetry  
- ❌ No external API calls  
- ❌ No logging of scan history

Everything happens in your browser’s memory. Once you close the tab, your scan data is gone unless you choose to copy it yourself.

---

## QR Scanner Notes

The QR scanner is **optional** and **local**:

- Uses `navigator.mediaDevices.getUserMedia` to access the camera *only* when you press **Start camera**  
- Stops the camera when you press **Stop** or hide the QR panel  
- Uses the browser’s native `BarcodeDetector` (where available) to decode QR codes  
- Allows QR image upload as a fallback when live camera scanning is not supported

If your browser does not support `BarcodeDetector`, the app will show a clear message and you can still paste or type URLs manually.

---

## Getting Started

1. **Download or clone** this repository.  
2. Open `index.html` in a modern browser (Chrome, Edge, Firefox, or a Chromium-based browser).  
3. Paste a URL into the scanner input on the **Scanner** page.  
4. Click **Analyze** to get a risk score, findings, and verdict.  
5. (Optional) Open the **QR scanner**, point it at a QR code, and analyze the decoded link.

> Tip: You can also use the **Copy last URL** control to quickly copy the last analyzed URL for sharing or reporting.

---

## File Layout

- `index.html` – Main UI and page structure (Home, About, Scanner).  
- `style.css` – Layout, theming, and visual styling (light + dark neon modes).  
- `proxuma.security.js` – Proxuma Security Engine – Heuristic v10 (core analysis logic).  
- `proxuma.ui.js` – UI bindings, navigation, theme toggle, URL + QR scan wiring, and result rendering.  
- `proxuma.signatures.json` – Lightweight keyword and extension deck used to support heuristic checks.  
- `README.md` – This documentation.

---

## Limitations & Scope

Proxuma Lite is **not**:

- A full antivirus solution  
- A network traffic inspector  
- A replacement for endpoint protection

It is a **link-intelligence helper**: a way to get a structured, understandable second opinion *before* you decide to trust or open a link.

Always combine Proxuma Lite with:

- Up-to-date browser and operating system  
- Device-level security controls  
- Healthy skepticism about unexpected or urgent messages

---

## License

This project is intended for personal, educational, and defensive security use.  
Please review the LICENSE file (or repository terms) for full details before distributing or embedding Proxuma Lite in other products.
