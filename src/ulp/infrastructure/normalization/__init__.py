"""
Normalization pipeline for ULP.

Provides a chain-of-responsibility pattern for normalizing log entries.
Each step transforms or enriches entries in sequence.
"""

from ulp.infrastructure.normalization.pipeline import NormalizationPipeline
from ulp.infrastructure.normalization.steps import (
    TimestampNormalizer,
    LevelNormalizer,
    FieldNormalizer,
    HostnameEnricher,
    GeoIPEnricher,
)

__all__ = [
    "NormalizationPipeline",
    "TimestampNormalizer",
    "LevelNormalizer",
    "FieldNormalizer",
    "HostnameEnricher",
    "GeoIPEnricher",
]
