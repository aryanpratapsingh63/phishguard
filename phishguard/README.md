# 🛡️ PHISHGUARD: Phishing URL Detection & Risk Analysis System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework: Flask](https://img.shields.io/badge/Framework-Flask%203.x-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Tests: Pytest](https://img.shields.io/badge/Tests-32%2F32%20Passed-brightgreen.svg)](https://docs.pytest.org/)
[![Security: Passive Analysis](https://img.shields.io/badge/Security-Zero%20Network%20Footprint-emerald.svg)](#defensive-security-philosophy)

> **PHISHGUARD** is a defensive, explainable cybersecurity web application designed to analyze URL strings and evaluate phishing risk without opening, executing, or connecting to the target website. It blends transparent rule-based threat attribution with empirical machine learning validation.

---

## 📌 Table of Contents
1. [Project Overview](#project-overview)
2. [Problem Statement](#problem-statement)
3. [Objectives](#objectives)
4. [Defensive Security Philosophy](#defensive-security-philosophy)
5. [Key Features](#key-features)
6. [System Architecture](#system-architecture)
7. [Detection Engine & Heuristics](#detection-engine--heuristics)
8. [Risk Scoring Methodology](#risk-scoring-methodology)
9. [Machine Learning Module](#machine-learning-module)
10. [Technology Stack](#technology-stack)
11. [Installation & Quickstart](#installation--quickstart)
12. [API Reference](#api-reference)
13. [Automated Testing](#automated-testing)
14. [Limitations & Future Scope](#limitations--future-scope)
15. [Academic Viva / Demo Guide](#academic-viva--demo-guide)

---

## 🎯 Project Overview

Social engineering and phishing attacks remain the primary entry point for over 80% of reported cyber breaches (Verizon DBIR). Adversaries craft deceptive domain names and weaponized links to steal enterprise credentials, spoof online banking portals, and distribute malicious payloads.

**PHISHGUARD** provides security analysts, IT administrators, and end-users with an **instant, zero-footprint URL triage tool**. Unlike traditional web browsers or sandbox tools that actively fetch web pages—thereby exposing the analyst to drive-by exploits, tracking beacons, or IP disclosure—PHISHGUARD parses and inspects the raw URL string strictly in-memory.

---

## ❗ Problem Statement

Most modern phishing detection tools fall into one of two extremes:
1. **Blacklist-dependent databases (e.g., DNSBL, Safe Browsing):** Vulnerable to zero-hour phishing campaigns where an attack domain exists for only 4 to 8 hours before detection.
2. **Opaque "Black-Box" ML Classifiers:** Neural networks or gradient-boosted trees that produce an arbitrary risk score without telling the security analyst *why* a URL is dangerous.

**The Solution:** PHISHGUARD bridges this gap by delivering **deterministic, explainable rule attribution** paired with **empirical machine learning benchmarks**, ensuring analysts understand exactly which lexical anomalies, protocol risks, or deception techniques triggered the risk rating.

---

## 🎯 Objectives

- **Safe Inspection:** Eliminate drive-by risks by executing 100% passive string-based feature extraction.
- **Explainability:** Attribute every single score point (0–100) to clear, human-understandable security indicators with educational context.
- **Defensive Triad:** Classify links into 3 distinct operational bands: `Likely Safe` (0–29), `Suspicious` (30–59), and `Potential Phishing` (60–100).
- **Auditability:** Maintain a local, privacy-preserving SQLite scan history without recording sensitive credentials, tokens, or cookies.
- **Empirical Validation:** Contrast the rule-based baseline against an empirical scikit-learn classifier with genuine Accuracy, Precision, Recall, F1, and Confusion Matrix metrics.

---

## 🔒 Defensive Security Philosophy

```
   [Untrusted Input URL]
             │
             ▼
   ┌───────────────────────────────────────────────┐
   │          ZERO NETWORK FOOTPRINT               │
   │  - NO HTTP/HTTPS requests sent                │
   │  - NO DNS queries performed                   │
   │  - NO WebSockets / Socket connections         │
   │  - NO Remote script or beacon execution       │
   └───────────────────────────────────────────────┘
             │
             ▼
   [In-Memory Lexical & Structural Parsing Only]
```

- **Safety First:** PHISHGUARD never visits the entered URL.
- **Privacy by Design:** URLs with embedded auth tokens are parsed and sanitized; session keys or personal data are never stored in the database.
- **Educational Context:** Every flagged anomaly explains *why* cybercriminals use it, fostering institutional cybersecurity awareness.

---

## ⚡ Key Features

1. **Modern Cybersecurity Dashboard:** Dark theme featuring high-contrast neon status badges, glassmorphic cards, responsive mobile layout, and quick-fill test presets.
2. **Multi-Vector Feature Extractor:** Inspects 18+ lexical, structural, and behavioral markers including:
   - IP address as hostname (IPv4 / IPv6 / integer hex)
   - Brand impersonation (e.g. brand in subdomain/path while apex domain is attacker-owned)
   - RFC 3986 userinfo `@` symbol deception
   - Punycode / IDN Homograph attacks (`xn--`)
   - High-abuse Top-Level Domains (TLDs)
   - URL shortener cloaking
   - Shannon Entropy analysis for DGA (Domain Generation Algorithms)
   - Subdomain depth stacking
   - Absence of TLS/HTTPS encryption
   - Phishing urgency trigger keywords
3. **Radial Risk Meter:** Visual score visualization from 0 to 100 with dynamic color classes.
4. **Actionable Security Guidance:** Context-aware defense recommendations instructing users on next steps.
5. **SQLite Audit Trail:** Searchable history log with aggregate statistics (total scans, safe count, average risk score) and JSON export.
6. **RESTful API:** Native `/api/analyze` endpoint for integration into external SIEM or SOC workflows.
7. **Empirical ML Module:** Real train/test split (75/25) on curated benchmark patterns calculating authentic metrics (Confusion Matrix, Precision, Recall, F1).

---

## 🏗️ System Architecture

```
                                  USER BROWSER
                         (HTML5 / CSS3 / Vanilla JS)
                                     │
                    HTTP GET / POST  │  JSON API
                                     ▼
                      ┌────────────────────────────┐
                      │    Flask Web Application   │
                      │          (app.py)          │
                      └──────────────┬─────────────┘
                                     │
           ┌─────────────────────────┼─────────────────────────┐
           ▼                         ▼                         ▼
┌─────────────────────┐   ┌─────────────────────┐   ┌─────────────────────┐
│  analyzer/          │   │  database/          │   │  ml/                │
│  ├── url_parser.py  │   │  └── db.py          │   │  ├── dataset.py     │
│  ├── feature_ext.py │   │                     │   │  ├── model.py       │
│  ├── risk_engine.py │   │  [SQLite Database]  │   │  └── train.py       │
│  └── tld_dataset.py │   │  (Audit Log Only)   │   │                     │
└─────────────────────┘   └─────────────────────┘   └─────────────────────┘
```

---

## 🔍 Detection Engine & Heuristics

| Indicator | Default Weight | Severity | Threat Rationale |
| :--- | :---: | :---: | :--- |
| **IP Address Hostname** | +40 pts | High | Attackers bypass domain registration and WHOIS records by routing victims directly to unmapped IPs. |
| **Brand Impersonation** | +35 pts | Critical | Embedding legitimate brands in subdomains (e.g. `paypal.com.attacker.com`) to mislead visual inspection. |
| **Credential `@` Symbol** | +35 pts | High | RFC 3986 treats text before `@` as login credentials, disguising the true destination host. |
| **Punycode / IDN Homograph** | +30 pts | High | Using lookalike Cyrillic/Greek characters (e.g. `xn--gogle-qoa.com`) to spoof legitimate domains. |
| **High-Abuse TLD** | +25 pts | Medium | Freenom (`.tk`, `.cf`) and cheap TLDs (`.top`, `.xyz`) statistically dominate disposable phishing sites. |
| **Phishing Urgency Keywords** | +10 to +20 pts | Medium | Words like `verify`, `banking`, `suspend`, `security`, `wallet` engineered to trigger panic reactions. |
| **Insecure HTTP Protocol** | +15 pts | Medium | Absence of TLS encryption allows man-in-the-middle interception and lacks certificate validation. |
| **URL Shortener Cloaking** | +15 pts | Medium | Services like `bit.ly` or `tinyurl.com` hide the final destination from email filters. |
| **Elevated Shannon Entropy** | +15 pts | Medium | High character randomness (> 3.9 bits) indicates automated Domain Generation Algorithms (DGA). |
| **Subdomain Stacking (>=3)** | +15 pts | Medium | Pushes true domain off-screen on mobile viewports and simulates corporate domain structures. |
| **Non-Standard Web Port** | +15 pts | Medium | Directing traffic to ports like `:8080` or `:8888` to evade enterprise proxy firewalls. |
| **Excessive URL Length** | +8 to +15 pts | Low/Med | Obscures parameters and pushes destination segments out of view. |

---

## 📊 Risk Scoring Methodology

The final risk score is clamped strictly between **0 and 100**:

$$\text{Final Risk Score} = \min\left(100, \sum_{i=1}^{n} w_i \cdot \mathbf{1}_{\{E_i\}}\right)$$

Where $w_i$ is the indicator weight and $\mathbf{1}_{\{E_i\}}$ is the indicator activation condition.

### Classification Bands:
- **`0 – 29: Likely Safe`** (Green): Follows standard web formatting, HTTPS, and regular domain structure.
- **`30 – 59: Suspicious`** (Amber): Contains multiple structural anomalies, URL shorteners, or sensitive keywords.
- **`60 – 100: Potential Phishing`** (Red): Triggers high-confidence malicious heuristics such as direct IP hosts, brand spoofing, or RFC credentials.

---

## 🛠️ Technology Stack

- **Backend:** Python 3.10+, Flask 3.x, Jinja2, Werkzeug
- **Storage:** SQLite 3 (native Python `sqlite3`)
- **Parsers:** `urllib.parse`, `ipaddress`, `re`, `math`
- **Machine Learning:** `scikit-learn`, `numpy`, `scipy` (with deterministic zero-dependency fallback)
- **Frontend:** HTML5, CSS3 Custom Properties, Vanilla JavaScript (ES6)
- **Testing:** `pytest` (32 automated unit and integration tests)

---

## 🚀 Installation & Quickstart

### Step 1: Clone or Navigate to Directory
```bash
cd phishguard
```

### Step 2: (Recommended) Create Virtual Environment
```bash
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run the Application
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## 🧪 Automated Testing

PHISHGUARD includes comprehensive automated tests covering parsing, security heuristics, risk scoring, SQLite persistence, and web routes.

To run the test suite:
```bash
python -m pytest tests/ -v
```

**Results:**
```text
tests/test_db.py ......................... PASSED
tests/test_feature_extractor.py .......... PASSED
tests/test_risk_engine.py ................ PASSED
tests/test_routes.py ..................... PASSED
tests/test_url_parser.py ................. PASSED

======================== 32 passed in 1.34s ========================
```

---

## 📡 RESTful API Reference

### Analyze URL
- **Endpoint:** `GET /api/analyze?url=<target_url>` or `POST /api/analyze`
- **Response Format:**
```json
{
  "status": "success",
  "is_valid": true,
  "url": "http://192.168.1.100/paypal/login.php",
  "hostname": "192.168.1.100",
  "risk_score": 85,
  "classification": "Potential Phishing",
  "summary_verdict": "High-severity risk indicators detected! This URL exhibits strong structural, lexical, or deceptive traits typical of phishing lures or malicious spoofing.",
  "indicators": [
    {
      "title": "IP Address Used as Hostname",
      "points": 40,
      "severity": "High",
      "description": "Direct IPv4 address '192.168.1.100' used instead of a registered domain name."
    },
    {
      "title": "Brand Impersonation Detected (Paypal)",
      "points": 35,
      "severity": "Critical",
      "description": "The brand keyword 'paypal' appears in the subdomain or path, but the registered domain is ''."
    }
  ],
  "recommendations": [
    "AVOID entering any usernames, passwords, or financial information on this website."
  ]
}
```

---

## ⚠️ Limitations & Future Scope

### Current Limitations:
1. **No Content Inspection:** Because PHISHGUARD does not open pages, it cannot inspect HTML DOM, form targets, or rendered CSS cloned pages.
2. **Dynamic Redirection:** Multi-hop redirects configured server-side cannot be traced without active requests.
3. **Shortener Unmasking:** Without making HEAD requests, shortened links are evaluated based on their masking behavior rather than their destination.

### Future Scope:
1. **Passive DNS / WHOIS Integration:** Add domain age checks (domains < 30 days old are heavily correlated with phishing).
2. **SSL Certificate Transparency Logs:** Query public CT logs (e.g. crt.sh) to verify SSL certificate issuer and validity dates without connecting to the server.
3. **Browser Extension:** Package PHISHGUARD's lexical parser into a Chrome Web Extension for real-time URL warning banners before navigation.

---

## 🎓 Academic Viva & Presentation Summary

- **Why rule-based over pure black-box ML?**  
  In cybersecurity, explainability is essential. A SOC analyst needs to defend actions to leadership. Saying *"the model outputted 0.82"* is unhelpful; saying *"the URL uses an IP address host, spoofed PayPal branding, and an unencrypted HTTP protocol with an RFC @ trick"* provides defensible triage evidence.
- **How does PHISHGUARD ensure safety during testing?**  
  Zero socket connections are opened to the submitted URL. Parsing relies exclusively on deterministic string manipulation (`urllib.parse`, regex, and `ipaddress`), guaranteeing immune execution.
