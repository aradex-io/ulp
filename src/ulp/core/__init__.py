"""
Core data models and base classes for ULP.
"""

from ulp.core.models import (
    LogEntry,
    LogLevel,
    LogSource,
    NetworkInfo,
    HTTPInfo,
    CorrelationIds,
    ParseResult,
    FormatSignature,
)
from ulp.core.base import BaseParser
from ulp.core.exceptions import (
    ULPError,
    ParseError,
    FormatDetectionError,
    ConfigurationError,
)
from ulp.core.security import (
    MAX_LINE_LENGTH,
    MAX_ORPHAN_ENTRIES,
    MAX_SESSION_GROUPS,
    MAX_JSON_DEPTH,
    LineTooLongError,
    SecurityValidationError,
    validate_line_length,
    validate_json_depth,
    validate_regex_pattern,
    sanitize_csv_cell,
    check_symlink,
)

__all__ = [
    "LogEntry",
    "LogLevel",
    "LogSource",
    "NetworkInfo",
    "HTTPInfo",
    "CorrelationIds",
    "ParseResult",
    "FormatSignature",
    "BaseParser",
    "ULPError",
    "ParseError",
    "FormatDetectionError",
    "ConfigurationError",
    # Security
    "MAX_LINE_LENGTH",
    "MAX_ORPHAN_ENTRIES",
    "MAX_SESSION_GROUPS",
    "MAX_JSON_DEPTH",
    "LineTooLongError",
    "SecurityValidationError",
    "validate_line_length",
    "validate_json_depth",
    "validate_regex_pattern",
    "sanitize_csv_cell",
    "check_symlink",
]
