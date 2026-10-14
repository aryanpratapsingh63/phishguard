import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Application configuration for PHISHGUARD."""
    SECRET_KEY = os.environ.get("PHISHGUARD_SECRET_KEY", "phishguard-defensive-cyber-key-2026")
    DATABASE_PATH = os.path.join(BASE_DIR, "data", "phishguard.db")
    MAX_URL_LENGTH = 2048
    
    # Risk Classification Thresholds
    RISK_SAFE_MAX = 29
    RISK_SUSPICIOUS_MAX = 59
    # 60 and above is Potential Phishing
    
    # Presets for demonstration and testing in UI
    SAMPLE_URLS = [
        {
            "category": "Legitimate",
            "url": "https://www.google.com/search?q=cybersecurity+best+practices",
            "description": "Standard legitimate search engine URL with HTTPS"
        },
        {
            "category": "Legitimate",
            "url": "https://en.wikipedia.org/wiki/Phishing",
            "description": "Educational resource URL with clean domain structure"
        },
        {
            "category": "Suspicious",
            "url": "http://tinyurl.com/secure-login-portal",
            "description": "URL shortener hiding destination, unencrypted HTTP, login keyword"
        },
        {
            "category": "Suspicious",
            "url": "http://free-gift-card-bonus.top/claim-now",
            "description": "Abused TLD (.top), marketing lure, unencrypted HTTP"
        },
        {
            "category": "Potential Phishing",
            "url": "http://192.168.1.105/paypal/account-verification/login.php",
            "description": "Direct IP address as host, PayPal brand spoofing in path, unencrypted HTTP"
        },
        {
            "category": "Potential Phishing",
            "url": "http://login-apple-support-verify.account-update.tk/signin.html?user=victim",
            "description": "Free abused TLD (.tk), excessive subdomains, brand impersonation, urgent keywords"
        },
        {
            "category": "Potential Phishing",
            "url": "https://microsoft-security-auth@malicious-redirect.com/login",
            "description": "Embedded credential '@' symbol used for deceptive visual spoofing"
        }
    ]
