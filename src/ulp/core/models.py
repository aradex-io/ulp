"""
Core data models for ULP.

These dataclasses define the normalized log entry schema and related structures.
All parsers convert their format-specific data into these common models.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

__all__ = [
    "LogLevel",
    "LogSource",
    "NetworkInfo",
    "HTTPInfo",
    "CorrelationIds",
    "LogEntry",
    "ParseResult",
    "FormatSignature",
]


class LogLevel(Enum):
    """
    Standard log levels mapped from various formats.

    Values are ordered by severity (higher = more severe).
    """
    TRACE = 0
    DEBUG = 10
    INFO = 20
    NOTICE = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    ALERT = 60
    EMERGENCY = 70
    UNKNOWN = -1

    @classmethod
    def from_string(cls, level: str) -> "LogLevel":
        """
        Parse level string from various formats.

        Handles: INFO, info, I, 6 (syslog), warn, warning, err, error, etc.

        Args:
            level: String representation of log level

        Returns:
            Corresponding LogLevel enum value
        """
        mapping = {
            # Standard names (lowercase)
            "trace": cls.TRACE,
            "debug": cls.DEBUG,
            "info": cls.INFO,
            "notice": cls.NOTICE,
            "warn": cls.WARNING,
            "warning": cls.WARNING,
            "error": cls.ERROR,
            "err": cls.ERROR,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
            "fatal": cls.CRITICAL,
            "alert": cls.ALERT,
            "emergency": cls.EMERGENCY,
            "emerg": cls.EMERGENCY,
            # Single character abbreviations
            "t": cls.TRACE,
            "d": cls.DEBUG,
            "i": cls.INFO,
            "n": cls.NOTICE,
            "w": cls.WARNING,
            "e": cls.ERROR,
            "c": cls.CRITICAL,
            "f": cls.CRITICAL,
            "a": cls.ALERT,
            # Syslog numeric priorities (RFC 5424)
            "0": cls.EMERGENCY,
            "1": cls.ALERT,
            "2": cls.CRITICAL,
            "3": cls.ERROR,
            "4": cls.WARNING,
            "5": cls.NOTICE,
            "6": cls.INFO,
            "7": cls.DEBUG,
        }
        return mapping.get(level.lower().strip(), cls.UNKNOWN)

    def __ge__(self, other: "LogLevel") -> bool:
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other: "LogLevel") -> bool:
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other: "LogLevel") -> bool:
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other: "LogLevel") -> bool:
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


@dataclass
class LogSource:
    """Metadata about where a log entry originated."""
    file_path: str | None = None
    line_number: int | None = None
    hostname: str | None = None
    service: str | None = None
    container_id: str | None = None
    pod_name: str | None = None
    namespace: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class NetworkInfo:
    """Network-related fields extracted from logs."""
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    user_agent: str | None = None
    referer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class HTTPInfo:
    """HTTP-specific fields for web server logs."""
    method: str | None = None
    path: str | None = None
    query_string: str | None = None
    status_code: int | None = None
    response_size: int | None = None
    response_time_ms: float | None = None
    http_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class CorrelationIds:
    """IDs for correlating logs across systems."""
    request_id: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    correlation_id: str | None = None
    session_id: str | None = None
    user_id: str | None = None
    transaction_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class LogEntry:
    """
    The universal normalized log entry.

    All format-specific parsers produce instances of this class.
    Fields are optional to accommodate different log types.
    """
    # Core fields
    id: UUID = field(default_factory=uuid4)
    raw: str = ""  # Original unparsed line

    # Temporal
    timestamp: datetime | None = None
    timestamp_precision: str = "unknown"  # ms, us, ns, s

    # Classification
    level: LogLevel = LogLevel.UNKNOWN
    format_detected: str = "unknown"

    # Content
    message: str = ""
    structured_data: dict[str, Any] = field(default_factory=dict)

    # Source metadata
    source: LogSource = field(default_factory=LogSource)

    # Network context (for access logs, firewalls, etc.)
    network: NetworkInfo | None = None

    # HTTP context (for web server logs)
    http: HTTPInfo | None = None

    # Correlation
    correlation: CorrelationIds = field(default_factory=CorrelationIds)

    # Parsing metadata
    parser_name: str = ""
    parser_confidence: float = 0.0  # 0.0 to 1.0
    parse_errors: list[str] = field(default_factory=list)

    # Custom fields (format-specific data that doesn't fit above)
    extra: dict[str, Any] = field(default_factory=dict)

    def is_error(self) -> bool:
        """Check if this is an error-level or higher entry."""
        return self.level >= LogLevel.ERROR

    def formatted_timestamp(self, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Return formatted timestamp string or placeholder."""
        if self.timestamp:
            return self.timestamp.strftime(fmt)
        return "-"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        result = {
            "id": str(self.id),
            "raw": self.raw,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "timestamp_precision": self.timestamp_precision,
            "level": self.level.name,
            "format_detected": self.format_detected,
            "message": self.message,
            "structured_data": self.structured_data,
            "source": self.source.to_dict(),
            "parser_name": self.parser_name,
            "parser_confidence": self.parser_confidence,
            "parse_errors": self.parse_errors,
            "extra": self.extra,
        }

        if self.network:
            result["network"] = self.network.to_dict()
        if self.http:
            result["http"] = self.http.to_dict()

        correlation_dict = self.correlation.to_dict()
        if correlation_dict:
            result["correlation"] = correlation_dict

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogEntry":
        """Deserialize from dictionary."""
        from dateutil.parser import parse as parse_date

        entry = cls()
        entry.id = UUID(data.get("id", str(uuid4())))
        entry.raw = data.get("raw", "")

        if data.get("timestamp"):
            entry.timestamp = parse_date(data["timestamp"])

        entry.timestamp_precision = data.get("timestamp_precision", "unknown")
        entry.level = LogLevel[data.get("level", "UNKNOWN")]
        entry.format_detected = data.get("format_detected", "unknown")
        entry.message = data.get("message", "")
        entry.structured_data = data.get("structured_data", {})

        if "source" in data:
            entry.source = LogSource(**data["source"])

        if "network" in data:
            entry.network = NetworkInfo(**data["network"])

        if "http" in data:
            entry.http = HTTPInfo(**data["http"])

        if "correlation" in data:
            entry.correlation = CorrelationIds(**data["correlation"])

        entry.parser_name = data.get("parser_name", "")
        entry.parser_confidence = data.get("parser_confidence", 0.0)
        entry.parse_errors = data.get("parse_errors", [])
        entry.extra = data.get("extra", {})

        return entry


@dataclass
class ParseResult:
    """Result of parsing a log file or stream."""
    entries: list[LogEntry]
    format_detected: str = "unknown"
    confidence: float = 0.0
    entry_count: int = 0
    error_count: int = 0
    source_file: str | None = None

    def __post_init__(self):
        if self.entry_count == 0:
            self.entry_count = len(self.entries)
        if self.error_count == 0:
            self.error_count = sum(1 for e in self.entries if e.parse_errors)

    def filter(self, level: LogLevel | None = None) -> "ParseResult":
        """Return new ParseResult with filtered entries."""
        entries = self.entries
        if level is not None:
            entries = [e for e in entries if e.level >= level]
        return ParseResult(
            entries=entries,
            format_detected=self.format_detected,
            confidence=self.confidence,
            source_file=self.source_file,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "format_detected": self.format_detected,
            "confidence": self.confidence,
            "entry_count": self.entry_count,
            "error_count": self.error_count,
            "source_file": self.source_file,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class FormatSignature:
    """
    Defines how to recognize a log format.
    Used by the detection engine.
    """
    name: str
    description: str

    # Detection patterns (in priority order)
    magic_patterns: list[str]  # Regex patterns that uniquely identify format
    line_patterns: list[str] = field(default_factory=list)  # Common patterns

    # Structural hints
    is_json: bool = False
    is_multiline: bool = False
    typical_line_length: tuple[int, int] = (50, 500)  # min, max

    # Parser binding
    parser_class: str = ""  # Fully qualified class name

    # Confidence modifiers
    weight: float = 1.0  # Higher = more confident when matched
