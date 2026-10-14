"""
Explainable Risk Scoring Engine for PHISHGUARD.
Calculates a 0-100 risk score with transparent indicator attribution,
human-readable rationale, severity categorization, and defense recommendations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from .url_parser import SafeParsedURL
from .feature_extractor import URLFeatures


@dataclass
class RiskIndicator:
    """Represents a specific detected security risk factor."""
    title: str
    points: int
    severity: str  # Critical, High, Medium, Low, Info
    description: str
    educational_note: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "points": self.points,
            "severity": self.severity,
            "description": self.description,
            "educational_note": self.educational_note
        }


@dataclass
class RiskReport:
    """Comprehensive risk assessment report."""
    score: int
    classification: str
    color_class: str
    badge_label: str
    summary_verdict: str
    indicators: List[RiskIndicator] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    parsed_data: Optional[SafeParsedURL] = None
    features: Optional[URLFeatures] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "classification": self.classification,
            "color_class": self.color_class,
            "badge_label": self.badge_label,
            "summary_verdict": self.summary_verdict,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "recommendations": self.recommendations,
            "indicators_count": len(self.indicators),
        }


def evaluate_url_risk(parsed: SafeParsedURL, features: URLFeatures) -> RiskReport:
    """
    Evaluates URL features and computes an explainable risk score (0-100).
    Every score point is backed by an explicit RiskIndicator.
    """
    indicators: List[RiskIndicator] = []
    raw_score = 0

    # 1. IP Address as Hostname (High / Critical)
    if features.is_ip_address:
        pts = 40
        raw_score += pts
        ver_str = f"IPv{features.ip_version}" if features.ip_version else "IP"
        indicators.append(RiskIndicator(
            title="IP Address Used as Hostname",
            points=pts,
            severity="High",
            description=f"Direct {ver_str} address '{parsed.hostname}' used instead of a registered domain name.",
            educational_note="Legitimate organizations rarely ask users to browse directly to IP addresses. Phishers use raw IPs to bypass domain registration oversight and DNS blacklists."
        ))

    # 2. Brand Spoofing in Subdomain or Path (Critical)
    if features.brand_in_subdomain_or_path and features.spoofed_brand:
        pts = 35
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Brand Impersonation Detected ({features.spoofed_brand.capitalize()})",
            points=pts,
            severity="Critical",
            description=f"The brand keyword '{features.spoofed_brand}' appears in the subdomain or path, but the registered domain is '{parsed.domain}.{parsed.tld}'.",
            educational_note="Attackers frequently embed recognizable brand names into subdomains (e.g. paypal.com.attacker.com) or paths to trick users at first glance into trusting the site."
        ))

    # 3. Userinfo '@' Symbol Deception (High)
    if features.has_at_symbol:
        pts = 35
        raw_score += pts
        indicators.append(RiskIndicator(
            title="Credential '@' Symbol in URL",
            points=pts,
            severity="High",
            description="The URL contains an '@' character which instructs browsers to treat prior text as authentication credentials rather than the destination host.",
            educational_note="In the RFC 3986 URL standard, text before '@' is treated as user credentials. Phishers craft URLs like 'https://google.com@evil-site.com' to deceive victims."
        ))

    # 4. Punycode / IDN Homograph Attack (High)
    if features.has_punycode:
        pts = 30
        raw_score += pts
        indicators.append(RiskIndicator(
            title="Punycode / IDN Homograph Encoding Detected",
            points=pts,
            severity="High",
            description=f"Hostname contains 'xn--' ({parsed.hostname}), indicating an Internationalized Domain Name.",
            educational_note="IDN homograph attacks substitute visually identical Cyrillic or Greek characters for Latin letters to create deceptive copycat domains (e.g. replacing 'o' with Cyrillic 'о')."
        ))

    # 5. Suspicious / Abused TLD (Medium)
    if features.is_suspicious_tld:
        pts = 25
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"High-Abuse Top-Level Domain (.{parsed.tld})",
            points=pts,
            severity="Medium",
            description=f"The domain uses '.{parsed.tld}', a TLD statistically overrepresented in phishing and malware campaigns.",
            educational_note="Certain TLDs offer free or ultra-low-cost registrations with lax verification, making them heavily favored by cybercriminals for disposable attack domains."
        ))

    # 6. Absence of HTTPS Encryption (Medium)
    if not features.has_https:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title="Insecure Protocol (Plain HTTP)",
            points=pts,
            severity="Medium",
            description="The URL uses unencrypted HTTP instead of HTTPS.",
            educational_note="Modern trustworthy services mandate TLS/HTTPS encryption. Plain HTTP exposes communications to interception, tampering, and lacks identity verification certificates."
        ))

    # 7. URL Shortener Service (Medium)
    if features.is_shortener:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title="URL Shortening Service Detected",
            points=pts,
            severity="Medium",
            description=f"The URL belongs to a shortening service ({parsed.hostname}) that masks the real destination.",
            educational_note="Shorteners are commonly leveraged in phishing SMS (smishing) and emails to bypass security filters and obscure suspicious domains from end users."
        ))

    # 8. Excessive Subdomains (Medium)
    if features.num_subdomains >= 3:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Excessive Subdomain Levels ({features.num_subdomains})",
            points=pts,
            severity="Medium",
            description=f"Hostname contains {features.num_subdomains} subdomain levels ('{parsed.subdomain}').",
            educational_note="Attackers stack multiple subdomains to mimic legitimate enterprise hierarchy or push the true domain off-screen on mobile viewports."
        ))
    elif features.num_subdomains == 2:
        pts = 5
        raw_score += pts
        # minor indicator, don't overwhelm with high alert

    # 9. Hyphens in Hostname (Low / Medium)
    if features.num_hyphens_hostname >= 2:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Multiple Hyphens in Hostname ({features.num_hyphens_hostname})",
            points=pts,
            severity="Medium",
            description=f"Domain contains {features.num_hyphens_hostname} hyphens ('{parsed.hostname}').",
            educational_note="Typosquatting and combo-squatting domains frequently stitch legitimate brand names with words like 'login-secure-account' using hyphens."
        ))
    elif features.num_hyphens_hostname == 1:
        pts = 5
        raw_score += pts

    # 10. Suspicious Authentication & Urgency Keywords
    kw_count = len(features.matched_suspicious_keywords)
    if kw_count >= 3:
        pts = 20
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Multiple Phishing Trigger Keywords Detected ({kw_count})",
            points=pts,
            severity="Medium",
            description=f"Found urgent action keywords: {', '.join(features.matched_suspicious_keywords)}.",
            educational_note="Phishing links often concentrate words associated with account emergencies, password resets, and verification to manufacture artificial urgency."
        ))
    elif kw_count in (1, 2):
        pts = 10
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Security/Authentication Keyword Detected ({', '.join(features.matched_suspicious_keywords)})",
            points=pts,
            severity="Low",
            description=f"URL contains sensitive workflow keywords: {', '.join(features.matched_suspicious_keywords)}.",
            educational_note="While common on legitimate login portals, authentication terms in unfamiliar URLs warrant caution."
        ))

    # 11. High Randomness / Hostname Entropy (Medium)
    if features.is_high_entropy:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"High Hostname Randomness / Entropy ({features.hostname_entropy})",
            points=pts,
            severity="Medium",
            description=f"Hostname demonstrates elevated character entropy ({features.hostname_entropy} bits), suggesting algorithmic generation.",
            educational_note="Domain Generation Algorithms (DGAs) and automated phishing toolkits generate pseudorandom character strings to evade signature-based blocklists."
        ))

    # 12. Non-Standard Web Port (Medium)
    if features.has_non_standard_port and features.port_number:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Non-Standard Port Specified (:{features.port_number})",
            points=pts,
            severity="Medium",
            description=f"URL directs connection to port {features.port_number} rather than standard port 80 (HTTP) or 443 (HTTPS).",
            educational_note="Adversaries host rogue phishing landing pages on non-standard ports to evade basic perimeter firewalls and web proxies."
        ))

    # 13. Excessive URL Length (Low / Medium)
    if features.url_length > 120:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title=f"Excessive Overall URL Length ({features.url_length} characters)",
            points=pts,
            severity="Medium",
            description="The URL string is unusually long (>120 characters).",
            educational_note="Long URLs are often used to conceal malicious payload parameters or push suspicious domain segments out of sight on short address bars."
        ))
    elif features.url_length > 75:
        pts = 8
        raw_score += pts

    # 14. Open Redirect / Double Slash in Path (Medium)
    if features.has_double_slash_redirect:
        pts = 15
        raw_score += pts
        indicators.append(RiskIndicator(
            title="Redirection Pattern (Double Slash '//' in Path)",
            points=pts,
            severity="Medium",
            description="URL path contains double slashes ('//') often used to facilitate open redirects.",
            educational_note="Open redirects allow attackers to leverage trusted domain names to bounce unsuspecting users onto external phishing sites."
        ))

    # 15. URL Encoding Obfuscation (Low)
    if features.has_percent_encoding:
        pts = 8
        raw_score += pts
        indicators.append(RiskIndicator(
            title="Hexadecimal URL Percent-Encoding Detected",
            points=pts,
            severity="Low",
            description="The URL contains hex-encoded characters (e.g., %20, %2f).",
            educational_note="Percent encoding is standard for special characters, but attackers use it to disguise malicious keywords, IP representations, or redirect destinations."
        ))

    # 16. Repeated Separators (Low)
    if features.has_repeated_dots or features.has_repeated_hyphens:
        pts = 10
        raw_score += pts
        indicators.append(RiskIndicator(
            title="Repeated Separators Detected ('..' or '--')",
            points=pts,
            severity="Low",
            description="Anomalous sequence of repeated separators found in the hostname or path.",
            educational_note="Repeated punctuation sequences are uncommon in legitimate hostnames and are characteristic of typosquatting or directory evasion attempts."
        ))

    # Clamp final score between 0 and 100
    final_score = min(100, max(0, raw_score))

    # Classification & Presentation Bands
    if final_score <= 29:
        classification = "Likely Safe"
        color_class = "safe"
        badge_label = "LIKELY SAFE"
        summary_verdict = "No significant phishing heuristics or anomalous indicators were detected. The URL appears structured according to standard web practices."
        recommendations = [
            "Always verify that the website displays a valid SSL/TLS lock icon before submitting information.",
            "Confirm the domain name matches the expected organization exactly before logging in.",
            "Maintain an updated browser and antivirus software with real-time web protection."
        ]
    elif final_score <= 59:
        classification = "Suspicious"
        color_class = "suspicious"
        badge_label = "SUSPICIOUS"
        summary_verdict = "Multiple anomalies or risk indicators were identified. The URL exhibits characteristics frequently associated with deceptive links or unverified endpoints."
        recommendations = [
            "Exercise heightened caution: Do NOT enter sensitive credentials, credit card details, or personal data.",
            "Verify the link's true origin by navigating to the official website directly via a search engine or bookmark.",
            "If this link arrived via email, SMS, or direct message, treat it as unverified and contact the sender out-of-band."
        ]
    else:
        classification = "Potential Phishing"
        color_class = "phishing"
        badge_label = "POTENTIAL PHISHING"
        summary_verdict = "High-severity risk indicators detected! This URL exhibits strong structural, lexical, or deceptive traits typical of phishing lures or malicious spoofing."
        recommendations = [
            "AVOID entering any usernames, passwords, or financial information on this website.",
            "DO NOT download files, enable notifications, or execute scripts from this location.",
            "Close this browser tab immediately and report the suspicious link to your organization's security team or IT helpdesk.",
            "If credentials have already been entered, immediately change your passwords from a known trusted device."
        ]

    # If no indicators were triggered, add an informational note
    if not indicators:
        indicators.append(RiskIndicator(
            title="Standard Web Structural Conventions",
            points=0,
            severity="Info",
            description="The URL uses standard domain conventions, standard port, and legitimate naming patterns.",
            educational_note="Even with a low score, always remember that zero-day phishing or compromised legitimate websites can host phishing content."
        ))

    return RiskReport(
        score=final_score,
        classification=classification,
        color_class=color_class,
        badge_label=badge_label,
        summary_verdict=summary_verdict,
        indicators=indicators,
        recommendations=recommendations,
        parsed_data=parsed,
        features=features
    )
