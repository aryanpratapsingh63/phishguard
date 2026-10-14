# 📑 ACADEMIC PROJECT REPORT
# PHISHGUARD: Phishing URL Detection & Risk Analysis System

**Domain:** Defensive Cybersecurity & Information Assurance  
**Academic Level:** Undergraduate / Graduate Capstone Project  
**Author:** Aryan  
**Technologies:** Python 3, Flask, SQLite, Lexical Heuristics, scikit-learn  

---

## Abstract

Phishing remains the predominant vector for cyber-attacks, responsible for significant identity theft, unauthorized account access, and corporate data breaches. Traditional defense mechanisms rely predominantly on static reputation blacklists, which suffer from a critical zero-hour detection window during which new phishing domains can operate undetected for several hours. Conversely, deep learning and ensemble machine learning approaches often operate as "black boxes," providing opaque prediction probabilities without actionable technical justifications for security operations center (SOC) analysts.

This report presents **PHISHGUARD**, an explainable, defensive cybersecurity web application that evaluates candidate URL strings locally and estimates their phishing risk without executing, visiting, or establishing socket connections to the target server. The system extracts 18+ lexical, structural, and behavioral markers, including raw IP hostnames, brand impersonation within subdomains, RFC 3986 credential syntax manipulation, high-abuse top-level domains (TLDs), and Shannon entropy for detecting algorithmic domain generation. The system couples a deterministic, rule-based scoring engine with an empirical Random Forest classifier for comparative benchmarking. Automated testing demonstrates a 100% pass rate across 32 unit and integration test cases, achieving 96.7% accuracy with 100% precision on held-out test evaluation.

---

## 1. Introduction

### 1.1 Background
The uniform resource locator (URL) is the fundamental addressing mechanism of the World Wide Web. However, the syntactic flexibility of the URL specification (RFC 3986) enables adversaries to craft deceptive strings that mislead users regarding the actual destination server. Phishing links masquerade as trusted banking portals, enterprise login pages, cloud storage services, and social media platforms to extract user credentials and session tokens.

### 1.2 Problem Statement
Investigating suspicious links poses severe operational challenges:
1. **Active Probe Risks:** If an analyst visits an untrusted link, their browser executes foreign client-side scripts, triggering drive-by downloads, fingerprinting attacks, or alerting the threat actor that the campaign is being investigated.
2. **Blacklist Inefficacy:** Modern phishing campaigns leverage disposable cloud domains and dynamic DNS, keeping each attack URL alive for fewer than 6 hours—well before commercial threat intelligence feeds update their lists.
3. **The Explainability Gap:** Black-box classifiers provide arbitrary probability scores without identifying which specific components of the URL triggered the alert.

### 1.3 Objectives
- Develop a strictly local, passive URL parsing and normalization pipeline that never sends network packets to the target.
- Extract 18+ explainable lexical, structural, and threat intelligence indicators.
- Design an explainable scoring engine that maps findings to a 0–100 scale categorized into `Likely Safe`, `Suspicious`, and `Potential Phishing`.
- Provide contextual remediation guidance for each detected indicator.
- Build an auditable, privacy-preserving SQLite scan history without recording credentials, tokens, or personal identifiers.
- Train an empirical scikit-learn Random Forest model on curated benchmark patterns to contrast deterministic heuristics with statistical learning.

---

## 2. Literature Review & Theoretical Foundations

### 2.1 Lexical & Structural Heuristics
Early research by Ma et al. (2009) established that URL lexical properties—such as length, delimiter frequencies, and character entropy—carry statistically significant predictive power for classifying malicious links. Phishing URLs typically exhibit:
- Unusually long hostnames or paths designed to disguise the actual destination on mobile screens.
- Excessive subdomains used to simulate legitimate organizational hierarchy (e.g., `www.paypal.com.account-update.xyz`).
- High-abuse Top-Level Domains (such as free Freenom TLDs `.tk`, `.ml` and low-cost gTLDs `.top`, `.click`, `.buzz`).

### 2.2 Shannon Entropy for Algorithmic Detection
To defeat domain reputation systems, malware authors and phishing kits utilize Domain Generation Algorithms (DGAs) that programmatically generate pseudorandom domain strings. Claude Shannon's Information Entropy quantifies the uncertainty or randomness of a string:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Standard English words and recognized corporate domain names exhibit low character entropy ($2.2 \text{ to } 3.4 \text{ bits}$), whereas algorithmically generated strings yield high entropy ($> 3.9 \text{ bits}$), providing a robust heuristic signal.

### 2.3 RFC 3986 Syntactic Ambiguities
Under RFC 3986 Section 3.2.1, a URL authority component may contain optional user information followed by an `@` character:
`scheme://user:password@host:port/path`
Web browsers treat text prior to the `@` as basic authentication credentials and navigate directly to the host specified *after* the `@`. Phishers exploit this syntax by crafting URLs such as:
`https://www.bankofamerica.com@malicious-harvesting-site.com/login`

---

## 3. System Architecture & Design

### 3.1 Architecture Overview
The system follows a modular architectural pattern consisting of four decoupled tiers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│        (HTML5, CSS3 Custom Properties, Vanilla JS)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON API
┌──────────────────────────────▼──────────────────────────────┐
│                    Flask Controller Tier                    │
│            (app.py - Routing, Validation, Errors)           │
└──────┬───────────────────────┬───────────────────────┬──────┘
       │                       │                       │
┌──────▼──────────────┐ ┌──────▼──────────────┐ ┌──────▼──────┐
│   Analyzer Core     │ │   Persistence Tier  │ │  ML Module  │
│ ├── url_parser      │ │ ├── db.py (SQLite)  │ │ ├── dataset │
│ ├── feature_extract │ │ └── phishguard.db   │ │ ├── model   │
│ └── risk_engine     │ └─────────────────────┘ │ └── train   │
└─────────────────────┘                         └─────────────┘
```

### 3.2 Database Schema
The scan history is maintained in SQLite with strict data privacy constraints:

```sql
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    normalized_url TEXT,
    hostname TEXT,
    risk_score INTEGER NOT NULL,
    classification TEXT NOT NULL,
    indicators_count INTEGER DEFAULT 0,
    indicators_summary TEXT,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_history(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_classification ON scan_history(classification);
```

---

## 4. Implementation Details

### 4.1 Safe Normalization Pipeline (`analyzer/url_parser.py`)
- Enforces an input cap of 2,048 characters to eliminate memory exhaustion vectors.
- Strips ASCII control characters (`\x00-\x1f\x7f`).
- Safely prepends `http://` if the protocol scheme was omitted by the user.
- Utilizes `urllib.parse.urlsplit` to isolate URL segments without invoking network resolvers.
- Evaluates hostname IP representation using `ipaddress.ip_address` for IPv4, IPv6, and integer decimal formats.
- Extracts apex domain, subdomains, and multi-part ccTLDs (`.co.uk`, `.gov.in`).

### 4.2 Explainable Risk Scoring Engine (`analyzer/risk_engine.py`)
The risk scoring engine computes an aggregated risk score bounded between 0 and 100:

$$\text{Final Score} = \min\left(100, \sum_{k=1}^{m} w_k \cdot \mathbf{1}_{\{I_k\}}\right)$$

Every point increment generates a structured `RiskIndicator` instance containing:
1. Indicator Title
2. Points Contributed ($w_k$)
3. Severity Classification (`Critical`, `High`, `Medium`, `Low`, `Info`)
4. Observed Description
5. Educational Cybersecurity Rationale

### 4.3 Classification Thresholds
- **`0 – 29: Likely Safe`** (Green): Conforms to standard web conventions and HTTPS encryption.
- **`30 – 59: Suspicious`** (Amber): Exhibits multiple structural anomalies, URL shorteners, or urgency triggers.
- **`60 – 100: Potential Phishing`** (Red): Triggers high-confidence malicious heuristics (direct IP host, brand impersonation, RFC credential spoofing).

---

## 5. Automated Testing & Verification

A comprehensive automated test suite consisting of 32 unit and integration tests was developed using `pytest`:

| Test Module | Coverage Scope | Tests | Pass Rate |
| :--- | :--- | :---: | :---: |
| `test_url_parser.py` | Empty strings, oversize URLs, missing schemes, IPv4/IPv6, Punycode, multi-part TLDs | 8 | 100% |
| `test_feature_extractor.py` | Protocol detection, IP parsing, keyword matching, brand spoofing, Shannon entropy | 7 | 100% |
| `test_risk_engine.py` | Score boundaries (0–100), band categorization, RFC trick scoring, recommendations | 5 | 100% |
| `test_db.py` | SQLite connection, saving scans, aggregation statistics, single deletion, history clear | 3 | 100% |
| `test_routes.py` | Flask index route, POST scan, JSON API, history, export, ML dashboard, custom 404 | 9 | 100% |
| **Total** | **Comprehensive Full System Coverage** | **32** | **100%** |

---

## 6. Experimental Results & ML Evaluation

The system was evaluated against a balanced benchmark dataset of 120 verified legitimate and phishing URL patterns using a 75/25 train-test split:

### 6.1 Evaluation Metrics (Actual Test Partition, N=30)
- **Model:** Random Forest Classifier (50 estimators, max depth 6)
- **Accuracy:** **96.67%**
- **Precision:** **100.00%**
- **Recall:** **93.33%**
- **F1-Score:** **96.55%**

### 6.2 Confusion Matrix
$$\begin{pmatrix} \text{True Negative (TN): 15} & \text{False Positive (FP): 0} \\ \text{False Negative (FN): 1} & \text{True Positive (TP): 14} \end{pmatrix}$$

### 6.3 Feature Importance Rankings
1. `is_ip_address`: **26.4%**
2. `brand_in_subdomain_or_path`: **22.1%**
3. `has_at_symbol`: **17.8%**
4. `is_suspicious_tld`: **13.5%**
5. `has_https`: **9.8%**
6. `num_suspicious_keywords`: **6.1%**

---

## 7. Viva Voce & Defense Q&A Preparation

### Q1: Why did you build a rule-based engine instead of solely using Deep Learning?
**Answer:**  
In cybersecurity operations, explainability is essential. When an incident responder blocks a link or isolates an executive workstation, they must document justifiable evidence for audit and compliance. A black-box neural network providing a score of 0.87 offers no defensible explanation. PHISHGUARD's rule engine attributes every point to verifiable markers (e.g. direct IP host, spoofed PayPal keyword in subdomain, RFC 3986 `@` syntax). Furthermore, rules can be updated in real time without retraining delays.

### Q2: How do you protect the analyst from being compromised when scanning malicious URLs?
**Answer:**  
PHISHGUARD operates strictly on passive string analysis. It never issues HTTP requests, does not resolve DNS records, and does not execute client-side scripts. By performing in-memory decomposition via `urllib.parse` and regex heuristics, the analyst's machine is completely insulated from drive-by downloads and tracking beacons.

### Q3: What is Shannon Entropy and why is it useful in URL detection?
**Answer:**  
Shannon Entropy measures the degree of character randomness in a string:
$H = -\sum p(x) \log_2 p(x)$. Legitimate enterprise hostnames are human-readable and exhibit lower entropy ($2.2 \text{ to } 3.4 \text{ bits}$). Threat actors employ Domain Generation Algorithms (DGAs) to generate pseudorandom domain names that produce entropy scores above $3.9 \text{ bits}$, signaling algorithmic generation.

### Q4: How does the system handle IDN homograph attacks?
**Answer:**  
Attackers substitute visually identical Cyrillic or Greek characters for Latin characters (e.g., Cyrillic 'а' instead of ASCII 'a'). PHISHGUARD inspects hostnames for the standard `xn--` Punycode prefix generated when internationalized characters are mapped to ASCII, assigning +30 risk points to homograph indicators.

### Q5: What are the main limitations of your system?
**Answer:**  
1. PHISHGUARD inspects only the URL string; it cannot evaluate page DOM content, form action endpoints, or rendered visuals.
2. It cannot follow multi-hop HTTP redirects without making network connections.
3. Sophisticated spear-phishing campaigns hosted on compromised legitimate domains with clean URL structures require secondary layers of defense (defense-in-depth).

---

## 8. Conclusion

PHISHGUARD successfully demonstrates that explainable, non-invasive lexical analysis provides a rapid, high-confidence first line of defense against malicious URLs. By bridging deterministic rule attribution with statistical machine learning validation, the project delivers an accessible, robust tool suitable for security education, incident triage, and enterprise awareness.
