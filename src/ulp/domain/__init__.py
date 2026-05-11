"""
Domain layer for ULP.

Contains core business entities and domain service protocols.
This layer has no dependencies on external frameworks or infrastructure.
"""

from ulp.domain.entities import (
    LogEntry,
    LogLevel,
    LogSource,
    NetworkInfo,
    HTTPInfo,
    CorrelationIds,
    CorrelationGroup,
    CorrelationResult,
    ParseResult,
)
from ulp.domain.services import (
    StreamProcessor,
    NormalizationStep,
    CorrelationStrategy,
    LogParser,
    LogSourcePort,
)

__all__ = [
    # Entities
    "LogEntry",
    "LogLevel",
    "LogSource",
    "NetworkInfo",
    "HTTPInfo",
    "CorrelationIds",
    "CorrelationGroup",
    "CorrelationResult",
    "ParseResult",
    # Service protocols
    "StreamProcessor",
    "NormalizationStep",
    "CorrelationStrategy",
    "LogParser",
    "LogSourcePort",
]
