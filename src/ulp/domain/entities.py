"""
Domain entities for ULP.

These are the core business objects that represent log data.
They are immutable value objects with no dependencies on infrastructure.
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
    "CorrelationGroup",
    "CorrelationResult",
    "ParseResult",
]


class LogLevel(Enum):
    """
    Standard log levels mapped from various formats.

    Values are ordered by severity (higher = more severe).
    Supports comparison operators for filtering (e.g., level >= LogLevel.ERROR).
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
            "information": cls.INFO,
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
            "panic": cls.EMERGENCY,
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

    def has_any_id(self) -> bool:
        """Check if any correlation ID is set."""
        return any([
            self.request_id, self.trace_id, self.span_id,
            self.correlation_id, self.session_id, self.user_id,
            self.transaction_id
        ])

    def get_primary_id(self) -> tuple[str, str] | None:
        """Get the first non-None correlation ID as (field_name, value)."""
        for field_name in ["request_id", "trace_id", "correlation_id", "transaction_id",
                           "span_id", "session_id", "user_id"]:
            value = getattr(self, field_name)
            if value:
                return (field_name, value)
        return None


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
class CorrelationGroup:
    """
    A group of related log entries.

    Created by correlation strategies when entries share a correlation ID
    or fall within a time window.
    """
    id: UUID = field(default_factory=uuid4)
    correlation_key: str = ""
    correlation_type: str = ""  # "request_id", "timestamp_window", "session"
    entries: list[LogEntry] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    time_range: tuple[datetime, datetime] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate derived fields after initialization."""
        if not self.sources and self.entries:
            self.sources = {
                e.source.file_path or e.source.service or "unknown"
                for e in self.entries
            }

        if not self.time_range and self.entries:
            timestamps = [e.timestamp for e in self.entries if e.timestamp]
            if timestamps:
                self.time_range = (min(timestamps), max(timestamps))

    def timeline(self) -> list[LogEntry]:
        """Return entries sorted chronologically."""
        return sorted(
            [e for e in self.entries if e.timestamp],
            key=lambda e: e.timestamp
        )

    def entry_count(self) -> int:
        """Number of entries in this group."""
        return len(self.entries)

    def duration_ms(self) -> float | None:
        """Duration of this correlation group in milliseconds."""
        if self.time_range:
            delta = self.time_range[1] - self.time_range[0]
            return delta.total_seconds() * 1000
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": str(self.id),
            "correlation_key": self.correlation_key,
            "correlation_type": self.correlation_type,
            "entry_count": self.entry_count(),
            "sources": list(self.sources),
            "time_range": [
                self.time_range[0].isoformat(),
                self.time_range[1].isoformat()
            ] if self.time_range else None,
            "duration_ms": self.duration_ms(),
            "metadata": self.metadata,
            "entries": [e.to_dict() for e in self.entries],
        }


@dataclass
class CorrelationResult:
    """
    Result of a correlation operation.

    Contains correlated groups and entries that couldn't be correlated.
    """
    groups: list[CorrelationGroup] = field(default_factory=list)
    orphan_entries: list[LogEntry] = field(default_factory=list)
    statistics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate statistics after initialization."""
        if not self.statistics:
            self.statistics = self._compute_statistics()

    def _compute_statistics(self) -> dict[str, Any]:
        """Compute correlation statistics."""
        total_entries = sum(len(g.entries) for g in self.groups) + len(self.orphan_entries)
        correlated_entries = sum(len(g.entries) for g in self.groups)

        return {
            "total_groups": len(self.groups),
            "total_entries": total_entries,
            "correlated_entries": correlated_entries,
            "orphan_entries": len(self.orphan_entries),
            "correlation_rate": correlated_entries / total_entries if total_entries > 0 else 0,
            "sources_covered": len({s for g in self.groups for s in g.sources}),
            "avg_group_size": correlated_entries / len(self.groups) if self.groups else 0,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "statistics": self.statistics,
            "groups": [g.to_dict() for g in self.groups],
            "orphan_count": len(self.orphan_entries),
        }


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
