"""
Automated unit tests for Feature Extractor module.
"""

import pytest
from analyzer.url_parser import parse_url
from analyzer.feature_extractor import extract_features, calculate_entropy


def test_https_detection():
    p_https = parse_url("https://example.com/test")
    f_https = extract_features(p_https)
    assert f_https.has_https is True

    p_http = parse_url("http://example.com/test")
    f_http = extract_features(p_http)
    assert f_http.has_https is False


def test_ip_hostname_detection():
    p_ip = parse_url("http://192.168.1.1/admin")
    f_ip = extract_features(p_ip)
    assert f_ip.is_ip_address is True
    assert f_ip.ip_version == 4

    p_domain = parse_url("https://example.com/admin")
    f_domain = extract_features(p_domain)
    assert f_domain.is_ip_address is False


def test_suspicious_keyword_detection():
    p = parse_url("http://account-update-portal.com/login/verify.html")
    f = extract_features(p)
    assert "login" in f.matched_suspicious_keywords
    assert "verify" in f.matched_suspicious_keywords or "update" in f.matched_suspicious_keywords


def test_brand_spoofing_in_subdomain_or_path():
    # Brand 'paypal' in subdomain while domain is 'attacker-site.com'
    p = parse_url("http://paypal.account-verify.attacker-site.com/auth")
    f = extract_features(p)
    assert f.brand_in_subdomain_or_path is True
    assert f.spoofed_brand == "paypal"

    # Legitimate paypal domain should NOT trigger spoofing flag
    p_legit = parse_url("https://www.paypal.com/signin")
    f_legit = extract_features(p_legit)
    assert f_legit.brand_in_subdomain_or_path is False


def test_at_symbol_detection():
    p = parse_url("https://paypal.com@malicious-redirect.com/login")
    f = extract_features(p)
    assert f.has_at_symbol is True


def test_shortener_detection():
    p = parse_url("http://tinyurl.com/xyz123")
    f = extract_features(p)
    assert f.is_shortener is True

    p2 = parse_url("https://bit.ly/secure-auth")
    f2 = extract_features(p2)
    assert f2.is_shortener is True


def test_shannon_entropy():
    # Repetitive characters should have low entropy
    low_ent = calculate_entropy("aaaaaaa")
    assert low_ent == 0.0

    # Randomized string has high entropy
    high_ent = calculate_entropy("x7k9p2m4q8v1")
    assert high_ent > 3.0
