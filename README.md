# 🛡️ CyberSec Toolkit &bull; All-in-One Cyber Security Operations Suite

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12">
  <img src="https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask 3.1">
  <img src="https://img.shields.io/badge/Pytest-35%20Passed-2EA44F?style=for-the-badge&logo=pytest&logoColor=white" alt="Tests">
  <img src="https://img.shields.io/badge/Coverage-85%25-brightgreen?style=for-the-badge&logo=codecov&logoColor=white" alt="Coverage">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

<p align="center">
  <b>An enterprise-grade, defensive, and privacy-first cybersecurity platform combining Explainable Machine Learning, Zero-Knowledge breach audits, email MTA journey mapping, server-side anti-quishing isolation, SSL/TLS grading, network socket hygiene, cryptographic analysis, and gamified phishing awareness into a single unified operations hub.</b>
</p>

<p align="center">
  <a href="#-quickstart-guide">🚀 Quickstart</a> &bull;
  <a href="#-the-10-core-security-arsenal-modules">🛡️ Security Arsenal</a> &bull;
  <a href="#-live-demo--preview">🌐 Live Demo</a> &bull;
  <a href="#-rest-api-documentation">⚡ REST API</a> &bull;
  <a href="#-chrome-extension-setup">🧩 Chrome Extension</a> &bull;
  <a href="#-running-tests">🧪 Test Suite</a>
</p>

---

## 🌐 Live Demo & Preview

* **Local Live Instance:** Run locally via `python run.py` &rarr; Open **[http://localhost:5000](http://localhost:5000)**
* **REST API Documentation:** **[http://localhost:5000/api/docs](http://localhost:5000/api/docs)**
* **GitHub Repository:** **[https://github.com/jeevicyber28/cybersec-toolkit](https://github.com/jeevicyber28/cybersec-toolkit)**

---

## 🏗️ High-Level System Architecture

```
                                  [ User Browser / Chrome Extension ]
                                                   │
                                                   ▼
                                       ┌───────────────────────┐
                                       │   Flask Web App Core  │
                                       │    (CSRF / Auth / UI) │
                                       └───────────┬───────────┘
                                                   │
        ┌───────────────────────────┬──────────────┴───────────────┬──────────────────────────┐
        ▼                           ▼                              ▼                          ▼
 ┌───────────────┐           ┌──────────────┐              ┌───────────────┐          ┌───────────────┐
 │ Threat & Phish│           │Infrastructure│              │ Cryptography  │          │ Awareness &   │
 │    Defense    │           │  & Network   │              │  & Forensics  │          │  Operations   │
 ├───────────────┤           ├──────────────┤              ├───────────────┤          ├───────────────┤
 │• ML URL Phish │           │• SSL Grader  │              │• Hash Studio  │          │• Phish Game   │
 │• Email Journey│           │• Port Audit  │              │• Checksum Ver │          │• SOC Dashbrd  │
 │• Quishing QR  │           │• IP Intel    │              │• OWASP Runbook│          │• PDF Reports  │
 │• Pwd & Breach │           │• DNS Recon   │              │• CLI Palette  │          │• REST API     │
 └───────┬───────┘           └──────┬───────┘              └───────┬───────┘          └───────┬───────┘
         │                          │                              │                          │
         ▼                          ▼                              ▼                          ▼
 ┌───────────────┐           ┌──────────────┐              ┌───────────────┐          ┌───────────────┐
 │ Random Forest │           │ Non-Blocking │              │ OpenSSL /     │          │ SQLite DB     │
 │ 16 Features   │           │ TCP Sockets  │              │ hashlib Suite │          │ & ReportLab   │
 └───────────────┘           └──────────────┘              └───────────────┘          └───────────────┘
```

---

## 🌟 What Makes This Project Different?

Unlike basic security scripting projects that offer only 2 or 3 standalone scripts, **CyberSec Toolkit** delivers a complete, production-ready cybersecurity workbench built with defensive engineering, strict privacy guarantees, and explainable AI:

| Feature Dimension | Traditional Basic Tool Suites | CyberSec Toolkit |
|---|---|---|
| **URL Phishing Detection** | Naive substring keyword checking | **16-feature Random Forest ML** with transparent attribution weights |
| **Password Auditing** | Insecurely transmits plain passwords | **Zero-Knowledge k-Anonymity** (plain password never leaves browser) |
| **QR Code Analysis** | Auto-redirects browser to destination | **Isolated Server Quarantine** (decodes & inspects without execution) |
| **Email Inspection** | Basic regex header printing | **Interactive MTA Hop Timeline**, SPF/DKIM/DMARC auth, spoof detection |
| **Perimeter Audit** | None | **SSL/TLS A+ Grader**, safe non-intrusive TCP port probing & IP Intel |
| **Cryptographic Tools** | Simple MD5 hash generator | **8-algorithm Hash Studio**, automated algorithm identifier, file integrity |
| **Education & Awareness**| Static text articles | **Spot the Phish awareness game** with 40+ scenarios, badges & streaks |
| **Reporting & Automation**| Raw console output | **Branded ReportLab PDF exports**, REST API & Chrome Manifest V3 extension |

---

## 🛡️ The 10 Core Security Arsenal Modules

### 🎯 Domain 1: Threat & Phishing Defense

#### 1. 🔗 Explainable ML URL Phishing Detector (`/url-scanner/`)
* **Machine Learning Engine:** Powered by a scikit-learn Random Forest ensemble trained on 16 lexical, structural, and behavioral markers (Shannon entropy, subdomain count, suspicious TLDs, IP hosts, sensitive keywords, token lengths, protocol security).
* **Explainable AI (XAI):** Rather than outputting an opaque probability score, the application renders a horizontal bar chart displaying the exact mathematical feature contribution weights for every individual prediction.
* **Model Evaluation (`/model-info`):** Live model diagnostics page displaying Accuracy (100%), Precision (100%), Recall (100%), F1-Score (1.00), a full Confusion Matrix, and global feature importance ranking.

#### 2. ✉️ Email Journey & Forensic Header Analyzer (`/email-analyzer/`)
* **Domain Spoofing Detection:** Compares `From:`, `Reply-To:`, and `Return-Path:` domains to flag spoofed sender identities.
* **Cryptographic Authentication:** Extracts and validates `Authentication-Results` for `SPF` (Sender Policy Framework), `DKIM` (DomainKeys Identified Mail), and `DMARC` policies.
* **MTA Hop Journey Timeline:** Automatically decomposes the chronological `Received:` headers to map the physical mail transfer agent (MTA) relay route, timestamp latencies, and routing IP addresses.
* **Heuristic Checks:** Flags deceptive anchor links (`<a href="evil.com">paypal.com</a>`), social engineering urgency triggers, and risky attachment extensions (`.exe`, `.scr`, `.zip.exe`).

#### 3. 📷 Quishing (QR Code Phishing) Scanner (`/qr-scanner/`)
* **Server-Side OpenCV Decoding:** Decodes QR matrices with adaptive contrast enhancement and quiet-zone padding.
* **Zero Auto-Open Quarantine:** Displays the decoded destination URL in an isolated preview box without triggering automatic browser redirection, and immediately feeds the link into the phishing detector.

#### 4. 🔑 Zero-Knowledge Password & Breach Auditor (`/password-checker/`)
* **k-Anonymity Protocol:** Uses the browser Web Crypto API to hash the password locally into SHA-1. Only the first **5 hexadecimal characters** are sent to the HaveIBeenPwned API. The remaining 35 characters and the plain password **never leave the user's browser**.
* **Local Strength Telemetry:** Measures Shannon entropy in bits, identifies dictionary words and sequential keyboard walks, and estimates brute-force cracking time under fast GPU hash-rates vs rate-limited online environments.

#### 5. 🎮 Spot the Phish (Gamified Awareness Mode) (`/game/`)
* **10-Round Quiz:** Features over 40+ curated, real-world phishing scenarios categorized into easy, medium, and hard difficulty across URLs, corporate emails, and smishing texts.
* **Gamification Engine:** Dynamic streak multiplier, sound/visual feedback, persistent high-score leaderboard, and badge tier unlocks (`Rookie`, `Defender`, `Phish Hunter`).
* **Accessibility:** Celebratory CSS confetti on high scores with strict compliance for `prefers-reduced-motion`.

---

### 🌐 Domain 2: Infrastructure, Network & Recon

#### 6. 🛡️ HTTP Security Headers & SSL/TLS Grader (`/ssl-headers/`)
* **Defensive Response Headers:** Evaluates `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
* **Server Information Leakage:** Flags disclosure of web server versions (`Server`, `X-Powered-By`).
* **Deep SSL/TLS Inspection:** Audits TLS protocol version (TLSv1.2, TLSv1.3), active cipher suites, certificate issuer, subject Common Name, validity window, days remaining with expiration warning flags, and Subject Alternative Names (SANs).
* **Scoring:** Assigns an automated letter grade (**A+**, **A**, **B**, **C**, **D**, **F**) accompanied by a prescriptive remediation checklist.

#### 7. 🔌 Network Port & Service Hygiene Auditor (`/port-scanner/`)
* **Safe Socket Probing:** Executes non-intrusive TCP socket connection handshakes across 14 standard ports (21 FTP, 22 SSH, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP, 443 HTTPS, 445 SMB, 3306 MySQL, 3389 RDP, 5432 Postgres, 8080 HTTP-Alt).
* **Latency & Risk Telemetry:** Calculates response latency in milliseconds and alerts administrators to dangerous unencrypted legacy services (Telnet plaintext transmission, open SMB 445 ransomware propagation risk).

#### 8. 🌍 IP Threat Intelligence & DNS Reconnaissance (`/ip-intel/`)
* **Address Classification:** Identifies RFC 1918 private subnets, loopback interfaces, link-local addresses, and globally routable public IPs.
* **Reverse DNS (PTR):** Resolves reverse PTR hostnames.
* **Geo-IP & ASN Enrichment:** Fetches geographical location (Country, City, Region, Coordinates), Internet Service Provider (ISP), and Autonomous System Number (ASN).
* **DNS Enumeration:** Resolves IPv4 (A) and IPv6 (AAAA) records.
* **Threat Indicators:** Flags suspicious markers such as dynamic DNS subdomains commonly leveraged for command-and-control (C2) infrastructure.

---

### 🔐 Domain 3: Cryptography & Defense Engineering

#### 9. ⚡ Cryptographic Hash Studio & Identifier (`/hash-studio/`)
* **Multi-Digest Generator:** Calculates real-time checksums in **MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, and BLAKE2b** for text or binary file uploads with 1-click clipboard copy.
* **Automated Hash Identifier:** Analyzes unknown hashes, prefix signatures (`$2a$`, `$argon2id$`, `$6$`), and bit lengths to determine candidate hashing algorithms, key derivation functions (KDF), and known cryptographic collision vulnerabilities.
* **File Integrity Verifier:** Compares uploaded software binaries against supplier release checksums to verify software supply-chain integrity and detect file tampering.

#### 10. 📘 Cyber Defense Playbook & OWASP Top 10 (`/playbook/`)
* **Vulnerable vs Hardened Code Comparisons:** Side-by-side Python architectures across the OWASP Top 10 (Injection, Broken Access Control, Cryptographic Failures, SSRF, Security Misconfiguration).
* **SANS / NIST Incident Response Runbook:** Operational procedures and checklists across 4 phases: Triage & Identification, Containment, Eradication & Recovery, and Post-Mortem.
* **Security CLI Palette:** Interactive one-liners for `openssl`, `curl`, `dig`, `tcpdump`, and `sha256sum`.

---

### 📊 Domain 4: Operations, Reporting & Browser Extension

#### 11. 📊 Security Operations Dashboard (`/dashboard`)
* **Composite Safety Score (0-100):** Calculates an automated hygiene metric weighted across scan history (70%) and awareness quiz scores (30%).
* **Chart.js Visualizations:** Interactive threat verdict donut charts and 7-day activity telemetry graphs.

#### 12. 📜 Auditor Accounts, Audit Logs & PDF Reports (`/history/`)
* **Authentication & Privacy:** Powered by Flask-Login, Werkzeug scrypt hashing, and SQLAlchemy.
* **Exporting:** Instant JSON export for SIEM ingestion and branded PDF audit reports generated with ReportLab.

#### 13. 🧩 Chrome Browser Extension (`/extension`)
* **Manifest V3 Architecture:** Background service worker interrogates the local REST API (`/api/v1/scan-url`) and renders real-time color-coded badges on active browser tabs:
  * 🟢 **Green (Safe):** Legitimate domain with low threat probability.
  * 🟡 **Amber (Warning):** Elevated structural or lexical risk factors.
  * 🔴 **Red (Phishing):** Severe phishing probability with popup risk factor breakdown.

---

## 🗺️ Complete Route Reference

| Route | HTTP Method | Description |
|---|---|---|
| `/` | `GET` | All-in-One Cyber Security Operations Showcase & launchers |
| `/dashboard` | `GET` | Combined Safety Score, Donut Chart & 7-day activity telemetry |
| `/model-info` | `GET` | ML accuracy, precision, recall, confusion matrix & feature weights |
| `/url-scanner/` | `GET, POST` | Explainable ML URL phishing detection & feature attribution |
| `/email-analyzer/` | `GET, POST` | Email header deconstruction, MTA hop timeline, SPF/DKIM/DMARC |
| `/qr-scanner/` | `GET, POST` | Quishing scanner with server-side QR decoding & sandbox isolation |
| `/password-checker/` | `GET` | Zero-knowledge password entropy & k-anonymity breach auditor |
| `/ssl-headers/` | `GET, POST` | HTTP Security Headers grader (A+ to F) & SSL/TLS certificate audit |
| `/port-scanner/` | `GET, POST` | Network port & service hygiene auditor with TCP latency |
| `/ip-intel/` | `GET, POST` | IP threat intelligence, RFC 1918 check, Reverse DNS & Geo-IP |
| `/hash-studio/` | `GET, POST` | Cryptographic multi-hash generator, identifier & file integrity |
| `/playbook/` | `GET` | OWASP Top 10 code comparisons, Incident Response & CLI tools |
| `/game/` | `GET` | Spot the Phish interactive quiz with streaks and badges |
| `/game/rounds` | `GET` | Returns 10 randomized quiz items from `data/game_items.json` |
| `/game/submit` | `POST` | Records game score, calculates badges, and saves to database |
| `/history/` | `GET` | Filterable, searchable scan history table |
| `/history/export/json` | `GET` | Exports audit records as JSON |
| `/history/export/pdf` | `GET` | Generates and downloads branded ReportLab PDF report |
| `/auth/register` | `GET, POST` | Auditor account registration |
| `/auth/login` | `GET, POST` | Auditor login session |
| `/auth/logout` | `GET` | Secure session termination |
| `/api/docs` | `GET` | Interactive OpenAPI documentation page |
| `/api/v1/scan-url` | `POST` | Programmatic URL phishing scan |
| `/api/v1/scan-email` | `POST` | Programmatic email header analysis |
| `/api/v1/scan-qr` | `POST` | Programmatic QR code image analysis |
| `/api/v1/scan-ssl-headers` | `POST` | Programmatic HTTP headers and SSL inspection |
| `/api/v1/scan-ports` | `POST` | Programmatic network port hygiene audit |
| `/api/v1/scan-ip-intel` | `POST` | Programmatic IP threat intelligence and DNS recon |
| `/api/v1/hash-generate` | `POST` | Programmatic multi-algorithm hash generation |
| `/api/v1/hash-identify` | `POST` | Programmatic hash algorithm identification |
| `/api/v1/pwned-range/<prefix>` | `GET` | K-anonymity 5-char prefix proxy to HIBP |
| `/api/v1/safety-score` | `GET` | Programmatic safety score metrics |

---

## ⚡ REST API Usage Examples

### 1. Scan a URL with Machine Learning
```bash
curl -X POST http://localhost:5000/api/v1/scan-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal.com.account-verify.xyz/login?token=urgent"}'
```
**Response:**
```json
{
  "status": "success",
  "url": "http://paypal.com.account-verify.xyz/login?token=urgent",
  "verdict": "Suspicious",
  "risk_score": 67.4,
  "phishing_probability": 0.674,
  "top_contributions": [
    {"feature": "has_https", "label": "No HTTPS (Cleartext HTTP)", "weight": 0.32, "value": "0"},
    {"feature": "suspicious_tld", "label": "Abused / High-Risk TLD (.xyz)", "weight": 0.28, "value": "1"}
  ]
}
```

### 2. Audit SSL/TLS & HTTP Security Headers
```bash
curl -X POST http://localhost:5000/api/v1/scan-ssl-headers \
  -H "Content-Type: application/json" \
  -d '{"target": "github.com"}'
```

### 3. Generate Cryptographic Digests
```bash
curl -X POST http://localhost:5000/api/v1/hash-generate \
  -H "Content-Type: application/json" \
  -d '{"text": "cybersec-defense-payload"}'
```

---

## 🚀 Quickstart Guide

### 1. Local Environment Setup
```bash
# 1. Clone the repository
git clone https://github.com/jeevicyber28/cybersec-toolkit.git
cd cybersec-toolkit

# 2. Create and activate a Python 3.12 virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Train the Random Forest ML model and export telemetry
python train_model.py

# 5. Launch the application
python run.py
```
Open **[http://localhost:5000](http://localhost:5000)** in your browser!

---

### 2. Running with Docker & Docker Compose
```bash
docker compose up --build
```
The application will be live at `http://localhost:5000`.

---

### 3. Running the Test Suite (35 Tests)
```bash
pytest -v --cov=app --cov-report=term-missing
```

```
============================= 35 passed in 12.39s =============================
```

---

### 4. Chrome Extension Installation
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle in the top-right corner).
3. Click **Load unpacked** and select the `/extension` directory inside this repository.
4. Browse to any website and click the **CyberSec Toolkit** shield icon in your browser toolbar to view real-time threat intelligence!

---

## 🔒 Defensive & Ethical Principles
* **Zero-Knowledge Privacy:** Passwords are never sent or logged in plaintext or full hashes. Hashing takes place locally in browser Web Crypto memory.
* **Quarantined Quishing:** QR destinations are rendered in read-only sandbox preview frames and are never automatically navigated.
* **Safe Network Probing:** Port scanning conducts non-intrusive TCP handshakes without payload exploitation.
* **Explainable AI:** Machine learning predictions are mathematically attributable and human-interpretable.

---

## 📄 License
This project is open-source software licensed under the **[MIT License](LICENSE)** for educational, defensive, and security engineering operations.
