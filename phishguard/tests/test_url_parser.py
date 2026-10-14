"""
Automated unit tests for URL Parsing, Normalization, and Safety Guards.
"""

import pytest
from analyzer.url_parser import parse_url, normalize_url, check_is_ip_address, split_domain_parts


def test_empty_and_whitespace_url():
    res1 = parse_url("")
    assert not res1.is_valid
    assert "empty" in res1.error_message.lower() or "valid" in res1.error_message.lower()

    res2 = parse_url("    ")
    assert not res2.is_valid
    assert res2.error_message is not None

    res3 = parse_url(None)
    assert not res3.is_valid


def test_excessive_length_url():
    oversized = "https://example.com/" + "a" * 2100
    res = parse_url(oversized, max_length=2048)
    assert not res.is_valid
    assert "maximum" in res.error_message.lower()


def test_missing_scheme_safe_handling():
    # User submits domain without http/https
    res = parse_url("paypal-security.com/login")
    assert res.is_valid
    assert res.hostname == "paypal-security.com"
    assert res.scheme == "http"


def test_valid_https_url():
    res = parse_url("https://www.google.com/search?q=cybersecurity")
    assert res.is_valid
    assert res.scheme == "https"
    assert res.hostname == "www.google.com"
    assert res.domain == "google"
    assert res.tld == "com"
    assert res.num_subdomains == 1
    assert not res.is_ip


def test_ipv4_host_parsing():
    res = parse_url("http://192.168.1.100:8080/admin/index.php")
    assert res.is_valid
    assert res.is_ip
    assert res.ip_version == 4
    assert res.hostname == "192.168.1.100"
    assert res.port == 8080


def test_ipv6_host_parsing():
    res = parse_url("http://[2001:db8::1]/login")
    assert res.is_valid
    assert res.is_ip
    assert res.ip_version == 6


def test_multi_part_tld():
    domain, subdomain, tld, parts = split_domain_parts("secure.banking.example.co.uk", is_ip=False)
    assert tld == "co.uk"
    assert domain == "example"
    assert subdomain == "secure.banking"
    assert parts == ["secure", "banking"]


def test_punycode_decoding():
    # IDN homograph test
    res = parse_url("http://xn--e1afmkfd.xn--p1ai/")
    assert res.is_valid
    assert "xn--" in res.hostname
