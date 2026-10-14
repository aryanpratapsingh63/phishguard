"""
Machine Learning package for PHISHGUARD.
Provides empirical classification metrics and comparison against rule-based engine.
"""

from .model import (
    train_and_evaluate_model,
    save_evaluation_metrics,
    load_cached_metrics,
    extract_numeric_vector,
    FEATURE_NAMES
)

__all__ = [
    "train_and_evaluate_model",
    "save_evaluation_metrics",
    "load_cached_metrics",
    "extract_numeric_vector",
    "FEATURE_NAMES"
]
