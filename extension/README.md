# 🛡️ CyberSec Shield - Browser Extension (Manifest V3)

A lightweight Chrome Manifest V3 browser extension that evaluates active browser tab URLs against the local CyberSec Toolkit ML API and displays real-time color-coded threat badges.

---

## 🌟 Features
- **Real-time Evaluation:** Checks active tab URLs automatically on load.
- **Dynamic Badge Alerts:**
  - 🟢 **SAFE (Green):** Low threat probability (< 35/100).
  - 🟡 **WARN (Amber):** Suspicious or unverified domain (35 - 64/100).
  - 🔴 **PHISH (Red):** Critical malicious indicators (>= 65/100).
- **Explainable Reasons:** Popup lists the top structural reasons for the assigned risk score.
- **Auditor Logging:** Supports optional `X-API-Key` to automatically record tab audits into your personal history database.

---

## 🚀 Installation Instructions (Chrome / Brave / Edge)
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` folder located within this project:
   ```
   cybersec-toolkit/extension
   ```
5. Pin **CyberSec Shield** to your browser toolbar!
6. Ensure your local CyberSec Toolkit server is running on `http://localhost:5000`.
