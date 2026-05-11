"""
Domain entities for ULP.

Base entity classes (LogEntry, LogLevel, etc.) are re-exported from
core.models as the canonical implementation. Only the domain-specific
aggregates CorrelationGroup and CorrelationResult are defined here.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from ulp.core.models import (
    LogLevel,
    LogSource,
    NetworkInfo,
    HTTPInfo,
    CorrelationIds,
    LogEntry,
    ParseResult,
)

__all__ = [
    "LogLevel", "LogSource", "NetworkInfo", "HTTPInfo",
    "CorrelationIds", "LogEntry", "ParseResult",
    "CorrelationGroup", "CorrelationResult",
]


def _normalize_ts(ts: datetime | None) -> datetime:
    """Return a timezone-aware datetime for comparison only; does not mutate the entry."""
    if ts is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


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
                self.time_range = (
                    min(timestamps, key=_normalize_ts),
                    max(timestamps, key=_normalize_ts),
                )

    def timeline(self) -> list[LogEntry]:
        """Return entries sorted chronologically."""
        return sorted(
            [e for e in self.entries if e.timestamp],
            key=lambda e: _normalize_ts(e.timestamp)
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

    @property
    def entry_count(self) -> int:
        """Total number of entries across all groups and orphans."""
        return self.statistics.get("total_entries", 0)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "statistics": self.statistics,
            "groups": [g.to_dict() for g in self.groups],
            "orphan_count": len(self.orphan_entries),
        }
