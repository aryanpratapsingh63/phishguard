"""
Feature extraction module for PHISHGUARD.
Extracts explainable lexical, structural, and heuristic indicators from parsed URLs.
"""

import math
import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import unquote

from .url_parser import SafeParsedURL
from .tld_dataset import (
    SUSPICIOUS_TLDS,
    SHORTENER_DOMAINS,
    TARGET_BRANDS,
    SUSPICIOUS_KEYWORDS,
)


@dataclass
class URLFeatures:
    """Dataclass holding all extracted features for risk analysis and ML."""
    # Lexical Lengths
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    
    # Character Counts
    num_dots_url: int
    num_dots_hostname: int
    num_hyphens_url: int
    num_hyphens_hostname: int
    num_underscores_url: int
    num_slashes_url: int
    num_digits_hostname: int
    hostname_digit_ratio: float
    
    # Structural & Protocol
    has_https: bool
    is_ip_address: bool
    ip_version: Optional[int]
    num_subdomains: int
    has_non_standard_port: bool
    port_number: Optional[int]
    
    # Obfuscation & Deception Tricks
    has_at_symbol: bool
    has_double_slash_redirect: bool
    has_percent_encoding: bool
    has_punycode: bool
    is_shortener: bool
    is_suspicious_tld: bool
    has_repeated_hyphens: bool
    has_repeated_dots: bool
    
    # Information & Randomness
    hostname_entropy: float
    is_high_entropy: bool
    
    # Keyword & Brand Intelligence
    matched_suspicious_keywords: List[str]
    matched_target_brands: List[str]
    brand_in_subdomain_or_path: bool
    spoofed_brand: Optional[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert features to dictionary."""
        return asdict(self)


def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon Entropy of a string.
    Higher entropy indicates greater randomness (e.g. DGA domains).
    """
    if not text:
        return 0.0

    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text.lower():
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def extract_features(parsed: SafeParsedURL) -> URLFeatures:
    """
    Extracts all explainable features from a SafeParsedURL.
    """
    url = parsed.normalized_url
    hostname = parsed.hostname
    path = parsed.path
    query = parsed.query
    tld = parsed.tld.lower()
    subdomain = parsed.subdomain.lower()

    # Lengths
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    # Character counts
    num_dots_url = url.count(".")
    num_dots_hostname = hostname.count(".")
    num_hyphens_url = url.count("-")
    num_hyphens_hostname = hostname.count("-")
    num_underscores_url = url.count("_")
    num_slashes_url = url.count("/")
    
    digits_in_host = sum(1 for c in hostname if c.isdigit())
    digit_ratio = round(digits_in_host / max(1, hostname_length), 3)

    # Protocol & Host checks
    has_https = parsed.scheme == "https"
    is_ip = parsed.is_ip
    ip_version = parsed.ip_version
    num_subdomains = parsed.num_subdomains

    # Port checks
    has_non_standard_port = False
    port_number = parsed.port
    if port_number is not None and port_number not in (80, 443):
        has_non_standard_port = True

    # Obfuscation tricks
    has_at_symbol = "@" in url
    
    # Check for // in path/query (open redirect / deceptive scheme)
    has_double_slash_redirect = "//" in path or "//" in query

    # Percent encoding check
    has_percent_encoding = bool(re.search(r"%[0-9a-fA-F]{2}", url))

    # Punycode / IDN
    has_punycode = "xn--" in hostname

    # URL Shortener check
    is_shortener = hostname in SHORTENER_DOMAINS or parsed.domain + "." + tld in SHORTENER_DOMAINS

    # Suspicious TLD check
    is_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Repeated separators
    has_repeated_hyphens = "--" in hostname or "--" in path
    has_repeated_dots = ".." in url

    # Entropy
    entropy = calculate_entropy(hostname.replace(".", ""))
    is_high_entropy = entropy >= 3.9 and hostname_length >= 10

    # Keyword analysis
    combined_search_space = f"{hostname} {path} {query}".lower()
    matched_keywords: List[str] = []
    for kw in SUSPICIOUS_KEYWORDS:
        # Match whole word or delimited pattern
        if re.search(r"(?:\b|_|-|/|=|\?)" + re.escape(kw) + r"(?:\b|_|-|/|&|\.|$)", combined_search_space):
            matched_keywords.append(kw)

    # Brand impersonation detection
    matched_brands: List[str] = []
    brand_in_sub_or_path = False
    spoofed_brand: Optional[str] = None

    registered_domain = parsed.domain.lower()

    # Check userinfo before @
    userinfo = ""
    if has_at_symbol:
        try:
            userinfo = url.split("@")[0].split("://")[-1].lower()
        except Exception:
            userinfo = ""

    for brand in TARGET_BRANDS:
        # If brand occurs in subdomain, path, or userinfo before @, but registered domain is NOT the brand:
        brand_in_sub = brand in subdomain
        brand_in_path = brand in path.lower()
        brand_in_user = bool(userinfo and brand in userinfo)
        
        if (brand_in_sub or brand_in_path or brand_in_user) and (registered_domain != brand):
            brand_in_sub_or_path = True
            spoofed_brand = brand
            matched_brands.append(brand)
        elif brand in hostname:
            matched_brands.append(brand)

    return URLFeatures(
        url_length=url_length,
        hostname_length=hostname_length,
        path_length=path_length,
        query_length=query_length,
        num_dots_url=num_dots_url,
        num_dots_hostname=num_dots_hostname,
        num_hyphens_url=num_hyphens_url,
        num_hyphens_hostname=num_hyphens_hostname,
        num_underscores_url=num_underscores_url,
        num_slashes_url=num_slashes_url,
        num_digits_hostname=digits_in_host,
        hostname_digit_ratio=digit_ratio,
        has_https=has_https,
        is_ip_address=is_ip,
        ip_version=ip_version,
        num_subdomains=num_subdomains,
        has_non_standard_port=has_non_standard_port,
        port_number=port_number,
        has_at_symbol=has_at_symbol,
        has_double_slash_redirect=has_double_slash_redirect,
        has_percent_encoding=has_percent_encoding,
        has_punycode=has_punycode,
        is_shortener=is_shortener,
        is_suspicious_tld=is_suspicious_tld,
        has_repeated_hyphens=has_repeated_hyphens,
        has_repeated_dots=has_repeated_dots,
        hostname_entropy=entropy,
        is_high_entropy=is_high_entropy,
        matched_suspicious_keywords=sorted(list(set(matched_keywords))),
        matched_target_brands=sorted(list(set(matched_brands))),
        brand_in_subdomain_or_path=brand_in_sub_or_path,
        spoofed_brand=spoofed_brand,
    )
