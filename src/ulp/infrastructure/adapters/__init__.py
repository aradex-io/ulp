"""
Infrastructure adapters for ULP.

Adapters implement the ports defined in the application layer,
connecting domain logic to external systems.
"""

from ulp.infrastructure.adapters.detection import FormatDetectorAdapter
from ulp.infrastructure.adapters.parser_registry import ParserRegistryAdapter

__all__ = [
    "FormatDetectorAdapter",
    "ParserRegistryAdapter",
]
