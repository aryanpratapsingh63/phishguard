# PHISHGUARD Data & Intelligence Directory

This directory stores:
1. `phishguard.db` - SQLite database storing user scan history (created automatically on first run).
2. `sample_urls.json` - Curated collection of verified test URLs for demonstrations and automated testing.

## Defensive Cybersecurity & Ethical Rules

1. **Passive Analysis Only**: No URL is ever fetched, pinged, or visited over HTTP/HTTPS/DNS.
2. **Privacy by Design**: PHISHGUARD does not store passwords, tokens, query authentication secrets, or cookies in SQLite scan history.
3. **No Malicious Payloads**: URLs included here are structural representations of phishing patterns documented by APWG, PhishTank, and cybersecurity research literature.
