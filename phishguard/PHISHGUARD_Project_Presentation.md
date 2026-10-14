# 📽️ PHISHGUARD: Project Presentation
## Phishing URL Detection & Risk Analysis System

---

### Slide 1: Title
- **Project Title:** PHISHGUARD: Phishing URL Detection & Risk Analysis System
- **Domain:** Defensive Cybersecurity & Information Assurance
- **Core Technology:** Python 3, Flask, SQLite, Lexical Heuristics, scikit-learn ML
- **Presenters:** Student Project Presentation / Defense Viva
- **Project Type:** College Final Year / Cybersecurity Capstone Project

---

### Slide 2: Introduction
- **What is PHISHGUARD?**  
  A defensive cybersecurity web application that analyzes URL strings locally and estimates whether a link is likely safe, suspicious, or potentially phishing.
- **Key Philosophy:**  
  100% passive in-memory analysis. The target URL is **never** visited, opened, or executed, protecting the security analyst from malware, drive-by downloads, and attacker telemetry beacons.
- **Core Deliverable:**  
  A complete, working application with an explainable rule engine, SQLite audit trail, machine learning evaluation module, and cybersecurity dashboard.

---

### Slide 3: Problem Statement
- Phishing remains the #1 initial access vector in cybersecurity breaches worldwide (over 80% of enterprise intrusions).
- Attackers exploit human trust and visual deception:
  - Deceptive subdomains (e.g. `paypal.com.attacker-controlled.net`)
  - Direct IP host routing to avoid domain registrar take-downs
  - RFC 3986 `@` symbol deception tricks
  - Character mimicry using Cyrillic homographs (Punycode `xn--`)
- Existing blacklist databases suffer from zero-hour latency (new phishing domains stay active for 4–8 hours before being listed).
- Black-box AI systems output opaque probabilities without explaining to security analysts *why* a link is dangerous.

---

### Slide 4: Objectives
1. **Zero Network Footprint:** Safely parse and decompose URL strings strictly in-memory without contacting remote servers.
2. **Transparent Explainability:** Attribute every point of a 0–100 risk score to specific, verifiable cyber threat indicators.
3. **Defensive Triad Classification:** Categorize links into 3 distinct operational bands:
   - `0–29`: Likely Safe
   - `30–59`: Suspicious
   - `60–100`: Potential Phishing
4. **Actionable Remediation:** Provide context-aware defensive recommendations for end users and SOC analysts.
5. **Auditable Logging:** Store query timestamps and scores locally in SQLite without storing sensitive passwords, tokens, or cookies.
6. **Empirical Benchmarking:** Compare the explainable rule baseline against an empirical scikit-learn classifier with genuine metrics.

---

### Slide 5: Existing Problem / Motivation
- **The Analyst Dilemma:**  
  When an employee forwards a suspicious email, opening the link to verify it risks corporate infection or alerts the attacker that their email campaign is being monitored.
- **The "Black-Box" Problem:**  
  Many modern ML models provide a probability score (e.g., "0.89 phishing") but cannot tell the SOC analyst what triggered the alert.
- **Our Motivation:**  
  Build a lightweight, reliable, and educational defense tool that combines deterministic rule explainability with statistical machine learning validation.

---

### Slide 6: Proposed Solution
- **PHISHGUARD: A Two-Pronged Hybrid Defense:**
  1. **Primary Operational Engine:** Deterministic, rule-based heuristic risk engine providing 100% transparent attribution.
  2. **Secondary Benchmarking Engine:** scikit-learn Random Forest classifier evaluating statistical feature correlations across 120 curated benchmark URLs.
- **User-Centric Web Interface:** Cyber-themed dark dashboard with live character counter, quick test presets, circular score gauges, and SQLite audit history.

---

### Slide 7: System Architecture
- **Layer 1: Presentation Layer:**  
  HTML5, CSS3 Custom Properties (cyber dark theme, glassmorphism), Vanilla JavaScript for live validation and preset selection.
- **Layer 2: Application Controller (Flask):**  
  Handles HTTP requests, JSON API endpoints, routing, and error boundaries.
- **Layer 3: Analysis Pipeline:**  
  - `Safe URL Normalizer & Parser`
  - `Multi-Vector Feature Extractor`
  - `Explainable Risk Scoring Engine`
- **Layer 4: Persistence & Intelligence:**  
  - Local SQLite scan history database (`phishguard.db`)
  - Curated threat intelligence datasets (risky TLDs, known brands, shorteners).

---

### Slide 8: Working Methodology
```
Step 1: Input Ingestion
        └── Validate length (<= 2048 chars), strip control characters
Step 2: Safe Decomposition
        └── Decompose into Scheme, Hostname, Port, Path, Subdomains, TLD
Step 3: Feature Extraction
        └── Extract 18+ lexical, structural, and behavioral markers
Step 4: Heuristic Scoring
        └── Calculate points with explicit severity weights
Step 5: Report Generation & Persistence
        └── Display radial score meter, reasons, recommendations, log to SQLite
```

---

### Slide 9: URL Features Extracted
- **Protocol:** HTTPS presence vs. insecure plain HTTP.
- **Host Characteristics:** Direct IPv4/IPv6 address, non-standard ports (e.g. `:8080`).
- **Domain Hierarchy:** Subdomain depth stacking, multi-part TLD parsing (`.co.uk`, `.gov.in`).
- **Obfuscation Tricks:** RFC `@` userinfo trick, URL shorteners (`bit.ly`), double-slash redirection (`//`).
- **Homograph Mimicry:** Punycode IDN detection (`xn--`).
- **Algorithmic Randomness:** Shannon Entropy of hostname to flag Domain Generation Algorithms (DGA).
- **Brand Spoofing:** Brand keyword in subdomain or path when registered domain is different.
- **Urgency Keywords:** Counts of sensitive terms (`login`, `verify`, `banking`, `password`, `update`).

---

### Slide 10: Risk Scoring Methodology
- **Scoring Scale:** Continuous scale from 0 to 100 points.
- **Mathematical Model:**
  $$\text{Score} = \min\left(100, \sum w_i \cdot I_i\right)$$
- **Indicator Weighting:**
  - Direct IP Host: **+40 pts** (High)
  - Brand Spoofing in Subdomain/Path: **+35 pts** (Critical)
  - Credential `@` Symbol: **+35 pts** (High)
  - Punycode IDN Homograph: **+30 pts** (High)
  - High-Abuse TLD (`.tk`, `.top`): **+25 pts** (Medium)
  - Insecure Plain HTTP: **+15 pts** (Medium)
  - URL Shortener Masking: **+15 pts** (Medium)
  - High Hostname Entropy (> 3.9): **+15 pts** (Medium)
  - Excessive Subdomains (>= 3): **+15 pts** (Medium)

---

### Slide 11: Technology Stack
- **Backend Framework:** Python 3.14 / Flask 3.1.3
- **Template Engine:** Jinja2
- **Database:** SQLite 3 (Built-in Python `sqlite3`)
- **Parsers:** `urllib.parse`, `ipaddress`, `re`, `math`
- **Machine Learning:** `scikit-learn 1.9.1`, `numpy 2.5.3`, `scipy 1.18.1`
- **Automated Testing:** `pytest 9.1.1`
- **Frontend:** HTML5, CSS3 (Custom Variables, Grid/Flexbox), Vanilla ES6 JavaScript

---

### Slide 12: UI Screens
1. **Home / Inspector Dashboard:**  
   Search input with real-time character counter, clear button, one-click preset test pills, and cybersecurity awareness notes.
2. **Scan Report View:**  
   Large animated circular risk score meter, classification badge, detailed indicator cards with severity levels and educational notes, and technical feature matrix.
3. **Audit History Log:**  
   Aggregate statistics widgets (Total scans, safe count, average score), real-time search filter, single-entry deletion, JSON export, and clear history modal.
4. **ML Benchmark Dashboard:**  
   Live accuracy, precision, recall, F1-score cards, interactive confusion matrix, and feature importance rankings.

---

### Slide 13: Testing & Quality Assurance
- **Automated Test Suite:** 32 unit and integration tests executed with `pytest`.
- **Test Coverage:**
  - `test_url_parser.py`: Empty strings, oversized URLs, missing schemes, IPv4/IPv6, Punycode.
  - `test_feature_extractor.py`: HTTPS, IP hosts, keywords, brand spoofing, Shannon entropy.
  - `test_risk_engine.py`: Score clamping (0–100), classifications, indicator attribution.
  - `test_db.py`: SQLite persistence, search queries, aggregate statistics, deletion.
  - `test_routes.py`: Web endpoints, REST API, error pages (404/500), CSV/JSON export.
- **Pass Rate:** **100% (32 / 32 tests passing)**.

---

### Slide 14: Experimental Results
- **Dataset:** 120 curated benchmark URLs (60 Legitimate, 60 Phishing patterns).
- **Train/Test Partition:** 75% Training (90 samples), 25% Testing (30 samples).
- **Rule-Based Engine Accuracy on Core Test Scenarios:** 100% on standard boundary test cases.
- **Empirical Random Forest Classifier Performance:**
  - Accuracy: **~96.7%**
  - Precision: **100.0%** (Zero False Positives on test set)
  - Recall: **~93.3%**
  - F1-Score: **~96.6%**
- **Top Discriminative Features Identified by Model:**
  1. `is_ip_address`
  2. `brand_in_subdomain_or_path`
  3. `has_at_symbol`
  4. `is_suspicious_tld`
  5. `has_https`

---

### Slide 15: Limitations
1. **No Remote DOM / Content Inspection:**  
   Cannot detect phishing pages hosted on compromised legitimate websites where the URL string appears completely normal.
2. **Dynamic Server Redirection:**  
   Cannot trace multi-hop server-side HTTP 302 redirects without opening the connection.
3. **Zero-Day Obfuscation Techniques:**  
   Advanced attackers who do not use obvious keywords or known brands require continuous threat intelligence updates.

---

### Slide 16: Future Scope
1. **Passive DNS & Domain Age Integration:**  
   Query public DNS over HTTPS (DoH) or WHOIS records to factor in domain registration age (domains created < 30 days ago are high risk).
2. **Certificate Transparency (CT) Log Querying:**  
   Check public SSL/TLS logs (e.g., crt.sh) to inspect certificate issuers without visiting the site.
3. **Browser Extension Packaging:**  
   Port PHISHGUARD's JavaScript/Python engine to a Chrome Extension to provide real-time URL warning banners before navigation.

---

### Slide 17: Conclusion
- PHISHGUARD demonstrates that **explainable, heuristic triage** provides a safe, highly effective first line of defense against phishing links.
- By eliminating network connections during analysis, security analysts are completely protected from drive-by attacks and attacker tracking.
- The dual-engine design marries deterministic explainability with empirical machine learning validation, making it an ideal capstone cybersecurity project.

---

### Slide 18: Thank You / Questions
- **Thank you for your time and attention!**
- **Demonstration:** Live walkthrough of PHISHGUARD dashboard and test cases.
- **Questions & Discussion (Viva Defense):** Ready for questions on URL parsing, Shannon entropy, risk weighting, and ML metrics.
