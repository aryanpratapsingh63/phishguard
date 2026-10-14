"""
Manual & Automated System Verification Script for PHISHGUARD.
Evaluates all sample URLs and prints comprehensive diagnostics.
"""

import json
from analyzer import parse_url, extract_features, evaluate_url_risk
from database import get_scan_stats

def main():
    print("=" * 80)
    print("PHISHGUARD - End-to-End System Verification")
    print("=" * 80)

    with open("data/sample_urls.json", "r", encoding="utf-8") as f:
        samples = json.load(f)

    print(f"{'Target URL':<50} | {'Score':<6} | {'Classification':<18} | {'Status'}")
    print("-" * 88)

    all_matched = True
    for item in samples:
        url = item["url"]
        expected = item["expected_classification"]
        p = parse_url(url)
        feats = extract_features(p)
        rep = evaluate_url_risk(p, feats)

        status = "MATCH" if rep.classification == expected else "MISMATCH"
        if status != "MATCH":
            all_matched = False

        short_url = (url[:47] + "...") if len(url) > 50 else url
        print(f"{short_url:<50} | {rep.score:<6} | {rep.classification:<18} | [{status}]")

    print("-" * 88)
    if all_matched:
        print("[SUCCESS] All sample test URLs matched expected risk classifications perfectly!")
    else:
        print("[WARNING] Some sample test URLs deviated from expected categories.")

    stats = get_scan_stats()
    print(f"[*] SQLite Scan Database Status: Total Scans Logged: {stats['total_scans']}")
    print("=" * 80)

if __name__ == "__main__":
    main()
