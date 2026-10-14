# 💻 PHISHGUARD: Windows Execution & Run Instructions

This guide provides step-by-step instructions for setting up, executing, and testing **PHISHGUARD** on Windows operating systems using PowerShell or Command Prompt.

---

## ⚡ Prerequisites

- **Operating System:** Windows 10 or Windows 11
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14 (Verified working on Python 3.14.7)
- **Terminal:** Windows PowerShell or Command Prompt (CMD)

---

## 🚀 Step 1: Open Terminal & Navigate to Project Directory

Open Windows PowerShell and navigate to the project directory:

```powershell
cd C:\Users\aryan\.gemini\antigravity\scratch\phishguard
```

Confirm that the project files are present:
```powershell
dir
```
*(You should see `app.py`, `config.py`, `requirements.txt`, `analyzer/`, `database/`, `ml/`, `templates/`, `static/`, and `tests/`)*

---

## 📦 Step 2: Install Required Dependencies

Run pip directly through Python to avoid PATH warnings:

```powershell
python -m pip install -r requirements.txt
```

*(This installs `Flask`, `pytest`, `scikit-learn`, `numpy`, and `scipy`)*

---

## 🧪 Step 3: Run the Automated Test Suite

Before starting the web server, verify that all 32 automated tests pass:

```powershell
python -m pytest tests/ -v
```

### Expected Output:
```text
============================= test session starts =============================
collected 32 items

tests/test_db.py::test_save_and_retrieve_scan PASSED                     [  3%]
tests/test_db.py::test_get_scan_stats_and_aggregation PASSED             [  6%]
tests/test_db.py::test_delete_and_clear_history PASSED                   [  9%]
tests/test_feature_extractor.py::test_https_detection PASSED             [ 12%]
tests/test_feature_extractor.py::test_ip_hostname_detection PASSED       [ 15%]
tests/test_feature_extractor.py::test_suspicious_keyword_detection PASSED [ 18%]
tests/test_feature_extractor.py::test_brand_spoofing_in_subdomain_or_path PASSED [ 21%]
tests/test_feature_extractor.py::test_at_symbol_detection PASSED         [ 25%]
tests/test_feature_extractor.py::test_shortener_detection PASSED         [ 28%]
tests/test_feature_extractor.py::test_shannon_entropy PASSED             [ 31%]
tests/test_risk_engine.py::test_safe_url_evaluation PASSED               [ 34%]
tests/test_risk_engine.py::test_suspicious_url_evaluation PASSED         [ 37%]
tests/test_risk_engine.py::test_potential_phishing_url_evaluation PASSED [ 40%]
tests/test_risk_engine.py::test_at_symbol_deception_risk PASSED          [ 43%]
tests/test_risk_engine.py::test_score_clamping PASSED                    [ 46%]
tests/test_routes.py::test_index_route PASSED                            [ 50%]
tests/test_routes.py::test_analyze_valid_url PASSED                      [ 53%]
tests/test_routes.py::test_analyze_phishing_url PASSED                   [ 56%]
tests/test_routes.py::test_analyze_empty_url PASSED                      [ 59%]
tests/test_routes.py::test_api_analyze_valid PASSED                      [ 62%]
tests/test_routes.py::test_api_analyze_invalid PASSED                    [ 65%]
tests/test_routes.py::test_history_and_clear_routes PASSED               [ 68%]
tests/test_routes.py::test_ml_dashboard_and_train_route PASSED           [ 71%]
tests/test_routes.py::test_404_error_page PASSED                         [ 75%]
tests/test_url_parser.py::test_empty_and_whitespace_url PASSED           [ 78%]
tests/test_url_parser.py::test_excessive_length_url PASSED               [ 81%]
tests/test_url_parser.py::test_missing_scheme_safe_handling PASSED       [ 84%]
tests/test_url_parser.py::test_valid_https_url PASSED                    [ 87%]
tests/test_url_parser.py::test_ipv4_host_parsing PASSED                  [ 90%]
tests/test_url_parser.py::test_ipv6_host_parsing PASSED                  [ 93%]
tests/test_url_parser.py::test_multi_part_tld PASSED                     [ 96%]
tests/test_url_parser.py::test_punycode_decoding PASSED                  [100%]

============================= 32 passed in 1.34s ==============================
```

---

## 🧠 Step 4: Run Machine Learning Benchmark (Optional CLI Runner)

To evaluate the Random Forest model on the benchmark dataset via the terminal:

```powershell
python ml/train.py
```

This will print the calculated **Accuracy, Precision, Recall, F1-Score, Confusion Matrix**, and **Feature Importance Rankings** directly to your console.

---

## 🌐 Step 5: Start the Flask Application Server

Launch the PHISHGUARD web application:

```powershell
python app.py
```

### Expected Console Output:
```text
=================================================================
 🛡️  PHISHGUARD: Phishing URL Detection & Risk Analysis System
 🔒  Defensive Cybersecurity Local Inspection Server
 🚀  Starting web application on http://127.0.0.1:5000
=================================================================
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

---

## 🖥️ Step 6: Access the Web Dashboard

Open your web browser (Chrome, Edge, Firefox) and go to:

👉 **`http://127.0.0.1:5000`**

### Features to Try in the Browser:
1. **Quick Test Presets:** Click on the preset pills under the search box (e.g. `Legitimate Google`, `IP Address Phishing`, or `Brand Spoofing`) to instantly populate the input and inspect results.
2. **Custom URL Analysis:** Paste any suspicious link from an email or message to view its 0–100 risk score and breakdown of triggered indicators.
3. **Audit History (`/history`):** Review previous inspection logs, search by keyword, export data to JSON, or clear history.
4. **Machine Learning Dashboard (`/ml`):** View real-time accuracy, confusion matrix, and feature importance rankings comparing the rule engine against Random Forest.
5. **REST API:** Test the JSON API by visiting:  
   `http://127.0.0.1:5000/api/analyze?url=http://192.168.1.100/paypal/login.php`

---

## 🛑 How to Stop the Server

Press **`Ctrl + C`** in your PowerShell terminal to gracefully shut down the Flask application.

---

## 🔧 Troubleshooting Common Windows Issues

### Issue 1: Port 5000 is already in use
If another application is using port 5000, start Flask on a different port:
```powershell
python -c "from app import app; app.run(port=5050)"
```
Then open `http://127.0.0.1:5050` in your browser.

### Issue 2: Script execution policy error
If activating a virtual environment returns an execution policy restriction:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Issue 3: SQLite database locked error
All database handles in PHISHGUARD use explicit `finally: conn.close()` blocks. If a file lock occurs after an abnormal termination, simply restart the terminal.
