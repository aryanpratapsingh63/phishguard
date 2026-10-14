"""
Automated unit tests for Risk Scoring Engine and Explainability Attribution.
"""

import pytest
from analyzer.url_parser import parse_url
from analyzer.feature_extractor import extract_features
from analyzer.risk_engine import evaluate_url_risk


def test_safe_url_evaluation():
    p = parse_url("https://www.google.com/search?q=cybersecurity")
    f = extract_features(p)
    report = evaluate_url_risk(p, f)

    assert 0 <= report.score <= 29
    assert report.classification == "Likely Safe"
    assert report.color_class == "safe"
    assert len(report.recommendations) > 0


def test_suspicious_url_evaluation():
    # Plain HTTP + URL shortener + keywords
    p = parse_url("http://tinyurl.com/account-verification-step1")
    f = extract_features(p)
    report = evaluate_url_risk(p, f)

    assert report.score >= 30
    assert report.classification in ("Suspicious", "Potential Phishing")
    assert any("Shortening" in ind.title or "Insecure" in ind.title for ind in report.indicators)


def test_potential_phishing_url_evaluation():
    # IP address + brand spoofing + plain HTTP + login keyword
    p = parse_url("http://192.168.1.100/paypal/login.php")
    f = extract_features(p)
    report = evaluate_url_risk(p, f)

    assert report.score >= 60
    assert report.classification == "Potential Phishing"
    assert report.color_class == "phishing"
    
    # Check that reasons/indicators mention IP and Brand
    titles = [ind.title for ind in report.indicators]
    assert any("IP Address" in t for t in titles)
    assert any("Brand" in t for t in titles)


def test_at_symbol_deception_risk():
    p = parse_url("https://paypal.com@evil-phishing-host.tk/login")
    f = extract_features(p)
    report = evaluate_url_risk(p, f)

    assert report.score >= 60
    assert report.classification == "Potential Phishing"
    assert any("@" in ind.title for ind in report.indicators)


def test_score_clamping():
    # Even if multiple heavy indicators fire, score must never exceed 100
    p = parse_url("http://192.168.1.100/paypal-security-login-verify-account-update-bank-confirm-password.tk@attack.icu:8080//redirect")
    f = extract_features(p)
    report = evaluate_url_risk(p, f)

    assert 0 <= report.score <= 100
