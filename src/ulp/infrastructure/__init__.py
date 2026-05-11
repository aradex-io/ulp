"""
Infrastructure layer for ULP.

Contains adapters that implement the ports defined in the application layer.
These connect the domain to external systems (files, network, etc.).
"""

from ulp.infrastructure.sources import (
    FileStreamSource,
    LargeFileStreamSource,
    ChunkedFileStreamSource,
    StdinStreamSource,
    BufferedStdinSource,
)
from ulp.infrastructure.correlation import (
    RequestIdCorrelation,
    TimestampWindowCorrelation,
    SessionCorrelation,
)
from ulp.infrastructure.normalization import (
    NormalizationPipeline,
    TimestampNormalizer,
    LevelNormalizer,
    FieldNormalizer,
    HostnameEnricher,
    GeoIPEnricher,
)
from ulp.infrastructure.adapters import (
    FormatDetectorAdapter,
    ParserRegistryAdapter,
)

__all__ = [
    # Sources
    "FileStreamSource",
    "LargeFileStreamSource",
    "ChunkedFileStreamSource",
    "StdinStreamSource",
    "BufferedStdinSource",
    # Correlation strategies
    "RequestIdCorrelation",
    "TimestampWindowCorrelation",
    "SessionCorrelation",
    # Normalization
    "NormalizationPipeline",
    "TimestampNormalizer",
    "LevelNormalizer",
    "FieldNormalizer",
    "HostnameEnricher",
    "GeoIPEnricher",
    # Adapters
    "FormatDetectorAdapter",
    "ParserRegistryAdapter",
]
