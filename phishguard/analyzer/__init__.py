"""
PHISHGUARD Analyzer Package
Defensive URL parsing, feature extraction, and risk assessment engine.
"""

from .url_parser import parse_url, SafeParsedURL
from .feature_extractor import extract_features, URLFeatures
from .risk_engine import evaluate_url_risk, RiskReport

__all__ = [
    "parse_url",
    "SafeParsedURL",
    "extract_features",
    "URLFeatures",
    "evaluate_url_risk",
    "RiskReport",
]
