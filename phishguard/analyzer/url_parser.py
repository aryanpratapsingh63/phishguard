"""
Safe URL parsing and normalization module for PHISHGUARD.
Performs strictly local, non-fetching string analysis and decomposition.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple
from urllib.parse import urlsplit, unquote

@dataclass
class SafeParsedURL:
    """Structured representation of safely parsed URL components."""
    is_valid: bool
    original_url: str
    normalized_url: str
    scheme: str
    netloc: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    domain: str
    subdomain: str
    tld: str
    subdomain_parts: List[str]
    num_subdomains: int
    is_ip: bool
    ip_version: Optional[int]
    error_message: Optional[str] = None


def normalize_url(raw_url: str) -> Tuple[str, bool]:
    """
    Safely normalizes raw input string.
    Returns (normalized_url, was_scheme_prepended).
    Does NOT connect to any network or resolve DNS.
    """
    if not raw_url:
        return "", False

    # Strip surrounding whitespace and unprintable control characters
    cleaned = raw_url.strip()
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned)

    # Check if a scheme is present
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", cleaned)
    prepended = False

    if not scheme_match:
        # Default to http:// for parsing purposes if missing
        cleaned = "http://" + cleaned
        prepended = True

    return cleaned, prepended


def check_is_ip_address(host_str: str) -> Tuple[bool, Optional[int]]:
    """
    Checks if a hostname is a direct IPv4 or IPv6 address.
    Handles bracketed IPv6 and standard dotted-quad IPv4.
    """
    if not host_str:
        return False, None

    cleaned_host = host_str.strip().strip("[]")

    # Quick test for IPv4 or IPv6
    try:
        ip_obj = ipaddress.ip_address(cleaned_host)
        return True, ip_obj.version
    except ValueError:
        pass

    # Check for hex/octal or decimal integer IP representations (e.g., 2130706433 = 127.0.0.1)
    if re.match(r"^\d{8,11}$", cleaned_host):
        try:
            ip_obj = ipaddress.ip_address(int(cleaned_host))
            return True, ip_obj.version
        except (ValueError, OverflowError):
            pass

    return False, None


def split_domain_parts(hostname: str, is_ip: bool) -> Tuple[str, str, str, List[str]]:
    """
    Splits hostname into (domain, subdomain, tld, subdomain_parts).
    e.g., 'secure.login.example.com' -> ('example', 'secure.login', 'com', ['secure', 'login'])
    """
    if not hostname or is_ip:
        return hostname or "", "", "", []

    parts = hostname.lower().split(".")
    if len(parts) <= 1:
        return hostname, "", "", []

    # Handle multi-part TLDs (e.g. .co.uk, .gov.uk, .com.au, .edu.in)
    multi_part_tlds = {
        "co.uk", "gov.uk", "ac.uk", "org.uk",
        "com.au", "net.au", "edu.au", "gov.au",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "co.nz", "com.br", "co.jp", "com.sg"
    }

    tld = ""
    domain = ""
    subdomain = ""
    sub_parts = []

    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in multi_part_tlds:
        tld = f"{parts[-2]}.{parts[-1]}"
        domain = parts[-3]
        sub_parts = parts[:-3]
    else:
        tld = parts[-1]
        domain = parts[-2]
        sub_parts = parts[:-2]

    subdomain = ".".join(sub_parts)
    return domain, subdomain, tld, sub_parts


def parse_url(raw_url: str, max_length: int = 2048) -> SafeParsedURL:
    """
    Safely parses and validates a URL string locally.
    Returns SafeParsedURL object.
    Never executes or sends network packets.
    """
    if raw_url is None:
        return SafeParsedURL(
            is_valid=False,
            original_url="",
            normalized_url="",
            scheme="",
            netloc="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment="",
            domain="",
            subdomain="",
            tld="",
            subdomain_parts=[],
            num_subdomains=0,
            is_ip=False,
            ip_version=None,
            error_message="URL cannot be empty."
        )

    raw_clean = raw_url.strip()
    if not raw_clean:
        return SafeParsedURL(
            is_valid=False,
            original_url="",
            normalized_url="",
            scheme="",
            netloc="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment="",
            domain="",
            subdomain="",
            tld="",
            subdomain_parts=[],
            num_subdomains=0,
            is_ip=False,
            ip_version=None,
            error_message="Please enter a valid URL."
        )

    if len(raw_clean) > max_length:
        return SafeParsedURL(
            is_valid=False,
            original_url=raw_clean[:100] + "... (truncated)",
            normalized_url="",
            scheme="",
            netloc="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment="",
            domain="",
            subdomain="",
            tld="",
            subdomain_parts=[],
            num_subdomains=0,
            is_ip=False,
            ip_version=None,
            error_message=f"URL exceeds maximum allowed length of {max_length} characters."
        )

    # Normalize safely
    normalized, was_prepended = normalize_url(raw_clean)

    try:
        split_res = urlsplit(normalized)
    except Exception as e:
        return SafeParsedURL(
            is_valid=False,
            original_url=raw_clean,
            normalized_url=normalized,
            scheme="",
            netloc="",
            hostname="",
            port=None,
            path="",
            query="",
            fragment="",
            domain="",
            subdomain="",
            tld="",
            subdomain_parts=[],
            num_subdomains=0,
            is_ip=False,
            ip_version=None,
            error_message=f"Malformed URL syntax: {str(e)}"
        )

    scheme = (split_res.scheme or "").lower()
    netloc = split_res.netloc or ""
    
    # Extract host and port safely
    try:
        hostname = split_res.hostname or ""
    except ValueError:
        # Invalid IPv6 or invalid netloc encoding
        hostname = netloc.split("@")[-1].split(":")[0]

    port = split_res.port

    if not hostname:
        # Check if user entered something like 'www.google.com'
        return SafeParsedURL(
            is_valid=False,
            original_url=raw_clean,
            normalized_url=normalized,
            scheme=scheme,
            netloc=netloc,
            hostname="",
            port=None,
            path=split_res.path or "",
            query=split_res.query or "",
            fragment=split_res.fragment or "",
            domain="",
            subdomain="",
            tld="",
            subdomain_parts=[],
            num_subdomains=0,
            is_ip=False,
            ip_version=None,
            error_message="Could not extract a valid host or domain from the input."
        )

    # Decode punycode if IDN
    try:
        hostname_ascii = hostname.encode("idna").decode("ascii").lower()
    except Exception:
        hostname_ascii = hostname.lower()

    is_ip, ip_version = check_is_ip_address(hostname_ascii)
    domain, subdomain, tld, sub_parts = split_domain_parts(hostname_ascii, is_ip)

    return SafeParsedURL(
        is_valid=True,
        original_url=raw_clean,
        normalized_url=normalized,
        scheme=scheme,
        netloc=netloc,
        hostname=hostname_ascii,
        port=port,
        path=split_res.path or "",
        query=split_res.query or "",
        fragment=split_res.fragment or "",
        domain=domain,
        subdomain=subdomain,
        tld=tld,
        subdomain_parts=sub_parts,
        num_subdomains=len(sub_parts),
        is_ip=is_ip,
        ip_version=ip_version,
        error_message=None
    )
