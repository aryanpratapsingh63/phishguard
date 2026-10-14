"""
Curated cyber threat intelligence datasets for URL heuristics.
Includes known high-abuse TLDs, URL shortening services, common phishing target brands,
and credential harvest keywords.
"""

# Frequently abused TLDs based on Spamhaus, APWG, and historical phishing reports
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",      # Free Freenom domains historically abused
    "top", "xyz", "work", "click", "buzz", "cam", "live", "icu",
    "loan", "fit", "country", "racing", "download", "stream",
    "accountant", "faith", "date", "review", "trade", "bid", "party",
    "surf", "rest", "bar", "link"
}

# Known URL shorteners that obscure genuine target destinations
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "adf.ly", "bit.do", "mcaf.ee", "rebrand.ly",
    "shorturl.at", "tiny.cc", "clck.ru", "v.gd"
}

# Top high-value brands frequently impersonated in phishing lures
TARGET_BRANDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "twitter", "linkedin",
    "chase", "bankofamerica", "wellsfargo", "citibank", "capitalone",
    "binance", "coinbase", "metamask", "steam", "adobe", "dropbox",
    "dhl", "fedex", "usps", "irs", "ebay", "yahoo", "outlook", "icloud"
}

# High-risk action/security keywords indicating urgency, authentication or credential harvesting
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "authenticate", "authentication", "update", "upgrade", "security",
    "secure", "account", "banking", "wallet", "recover", "recovery",
    "confirm", "confirmation", "billing", "invoice", "payment",
    "password", "passcode", "credential", "suspend", "suspended",
    "unusual", "activity", "support-desk", "helpdesk", "reactivate",
    "validation", "validate", "token", "session", "renew"
}
