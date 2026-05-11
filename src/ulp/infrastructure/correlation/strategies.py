"""
Correlation strategy implementations.

Provides three strategies for correlating log entries:
1. RequestIdCorrelation - Groups by shared correlation IDs
2. TimestampWindowCorrelation - Groups by temporal proximity
3. SessionCorrelation - Groups by user/session identifier
"""

import warnings
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterator
from uuid import uuid4

from ulp.domain.entities import LogEntry, CorrelationGroup
from ulp.domain.services import CorrelationStrategy
from ulp.core.security import MAX_ORPHAN_ENTRIES, MAX_SESSION_GROUPS

__all__ = [
    "RequestIdCorrelation",
    "TimestampWindowCorrelation",
    "SessionCorrelation",
]


class RequestIdCorrelation(CorrelationStrategy):
    """
    Correlate logs by shared request/trace/correlation IDs.

    This is the most reliable correlation strategy when IDs are present.
    Looks for common ID fields across log entries and groups them.

    Example:
        strategy = RequestIdCorrelation(["request_id", "trace_id", "correlation_id"])
        for group in strategy.correlate(entries):
            print(f"Request {group.correlation_key}: {len(group.entries)} logs")
    """

    def __init__(
        self,
        id_fields: list[str] | None = None,
        max_orphans: int = MAX_ORPHAN_ENTRIES,
    ):
        """
        Initialize request ID correlation.

        Args:
            id_fields: List of field names to check for IDs.
                       Defaults to common ID fields.
            max_orphans: Maximum orphan entries to track (H2 security limit)
        """
        self.id_fields = id_fields or [
            "request_id",
            "trace_id",
            "correlation_id",
            "span_id",
            "transaction_id",
            "x_request_id",
        ]
        self.max_orphans = max_orphans
        self._orphan_overflow_warned = False

    @property
    def name(self) -> str:
        return "request_id"

    def supports_streaming(self) -> bool:
        # Cannot stream - need to see all entries to group by ID
        return False

    def correlate(
        self,
        entries: Iterator[LogEntry] | list[LogEntry],
        buffer_size: int = 10000
    ) -> Iterator[CorrelationGroup]:
        """
        Group entries by shared correlation IDs.

        Args:
            entries: Log entries to correlate
            buffer_size: Maximum entries to buffer (for memory safety)

        Yields:
            CorrelationGroup for each unique ID found
        """
        # Group by ID value
        id_groups: dict[str, list[LogEntry]] = defaultdict(list)
        orphans: list[LogEntry] = []
        count = 0

        for entry in entries:
            count += 1
            if count > buffer_size:
                # Memory safety: yield current groups and reset
                yield from self._emit_groups(id_groups)
                id_groups = defaultdict(list)
                count = 0

            # Find first matching ID field
            entry_id = self._extract_id(entry)
            if entry_id:
                id_groups[entry_id].append(entry)
            else:
                # H2: Bound orphan list to prevent memory exhaustion
                if len(orphans) < self.max_orphans:
                    orphans.append(entry)
                elif not self._orphan_overflow_warned:
                    warnings.warn(
                        f"Orphan entry limit ({self.max_orphans}) exceeded. "
                        "Additional entries without correlation IDs will be dropped.",
                        UserWarning,
                        stacklevel=2,
                    )
                    self._orphan_overflow_warned = True

        # Emit remaining groups
        yield from self._emit_groups(id_groups)

    def _extract_id(self, entry: LogEntry) -> str | None:
        """Extract correlation ID from entry."""
        # Check correlation first (the correct field name)
        if entry.correlation:
            if entry.correlation.request_id:
                return entry.correlation.request_id
            if entry.correlation.trace_id:
                return entry.correlation.trace_id
            if entry.correlation.correlation_id:
                return entry.correlation.correlation_id
            if entry.correlation.session_id:
                return entry.correlation.session_id

        # Check structured data
        for field in self.id_fields:
            if field in entry.structured_data:
                return str(entry.structured_data[field])

        return None

    def _emit_groups(
        self,
        id_groups: dict[str, list[LogEntry]]
    ) -> Iterator[CorrelationGroup]:
        """Convert ID groups to CorrelationGroup objects."""
        for correlation_key, entries in id_groups.items():
            if len(entries) > 1:  # Only emit groups with multiple entries
                yield self._create_group(correlation_key, entries)

    def _create_group(
        self,
        correlation_key: str,
        entries: list[LogEntry]
    ) -> CorrelationGroup:
        """Create a CorrelationGroup from entries."""
        # Calculate time range
        timestamps = [e.timestamp for e in entries if e.timestamp]
        time_range = None
        if timestamps:
            time_range = (min(timestamps), max(timestamps))

        # Collect unique sources
        sources = {e.source.file_path or "<unknown>" for e in entries}

        return CorrelationGroup(
            id=uuid4(),
            correlation_key=correlation_key,
            correlation_type="request_id",
            entries=entries,
            sources=sources,
            time_range=time_range,
        )


class TimestampWindowCorrelation(CorrelationStrategy):
    """
    Correlate logs by temporal proximity.

    Groups entries that occur within a time window of each other.
    Useful when no explicit IDs exist but timing indicates relationship.

    Example:
        strategy = TimestampWindowCorrelation(window_seconds=1.0)
        for group in strategy.correlate(entries):
            print(f"Window {group.time_range}: {len(group.entries)} logs")
    """

    def __init__(
        self,
        window_seconds: float = 1.0,
        min_group_size: int = 2,
        require_multiple_sources: bool = True
    ):
        """
        Initialize timestamp window correlation.

        Args:
            window_seconds: Maximum time gap between related entries
            min_group_size: Minimum entries to form a group
            require_multiple_sources: Only group if entries from different sources
        """
        self.window_seconds = window_seconds
        self.window = timedelta(seconds=window_seconds)
        self.min_group_size = min_group_size
        self.require_multiple_sources = require_multiple_sources

    @property
    def name(self) -> str:
        return "timestamp_window"

    def supports_streaming(self) -> bool:
        # Can stream if entries arrive in timestamp order
        return True

    def correlate(
        self,
        entries: Iterator[LogEntry] | list[LogEntry],
        buffer_size: int = 10000
    ) -> Iterator[CorrelationGroup]:
        """
        Group entries by temporal proximity.

        Assumes entries are roughly timestamp-ordered for streaming.

        Args:
            entries: Log entries to correlate
            buffer_size: Window buffer size

        Yields:
            CorrelationGroup for each time window
        """
        current_window: list[LogEntry] = []
        window_start: datetime | None = None

        for entry in entries:
            if entry.timestamp is None:
                continue  # Skip entries without timestamps

            if window_start is None:
                # Start new window
                window_start = entry.timestamp
                current_window = [entry]
            elif entry.timestamp - window_start <= self.window:
                # Entry within window
                current_window.append(entry)
            else:
                # Entry outside window - emit current and start new
                group = self._maybe_create_group(current_window)
                if group:
                    yield group

                window_start = entry.timestamp
                current_window = [entry]

            # Memory safety: emit if buffer too large
            if len(current_window) >= buffer_size:
                group = self._maybe_create_group(current_window)
                if group:
                    yield group
                current_window = []
                window_start = None

        # Emit final window
        if current_window:
            group = self._maybe_create_group(current_window)
            if group:
                yield group

    def _maybe_create_group(
        self,
        entries: list[LogEntry]
    ) -> CorrelationGroup | None:
        """Create group if it meets criteria."""
        if len(entries) < self.min_group_size:
            return None

        sources = {e.source.file_path or "<unknown>" for e in entries}

        if self.require_multiple_sources and len(sources) < 2:
            return None

        timestamps = [e.timestamp for e in entries if e.timestamp]
        time_range = (min(timestamps), max(timestamps)) if timestamps else None

        # Use time range as correlation key
        key = f"{time_range[0].isoformat()}" if time_range else str(uuid4())

        return CorrelationGroup(
            id=uuid4(),
            correlation_key=key,
            correlation_type="timestamp_window",
            entries=entries,
            sources=sources,
            time_range=time_range,
            metadata={"window_seconds": self.window_seconds},
        )


class SessionCorrelation(CorrelationStrategy):
    """
    Correlate logs by user or session identifier.

    Groups entries belonging to the same user session, even if
    they span multiple requests.

    Example:
        strategy = SessionCorrelation(["user_id", "session_id", "client_ip"])
        for group in strategy.correlate(entries):
            print(f"Session {group.correlation_key}: {len(group.entries)} logs")
    """

    def __init__(
        self,
        session_fields: list[str] | None = None,
        session_timeout_minutes: int = 30,
        max_sessions: int = MAX_SESSION_GROUPS,
    ):
        """
        Initialize session correlation.

        Args:
            session_fields: Fields that identify a session
            session_timeout_minutes: Max gap before new session
            max_sessions: Maximum session groups to track (H3 security limit)
        """
        self.session_fields = session_fields or [
            "session_id",
            "user_id",
            "client_ip",
            "user_agent",
        ]
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self.max_sessions = max_sessions
        self._session_overflow_warned = False

    @property
    def name(self) -> str:
        return "session"

    def supports_streaming(self) -> bool:
        return False  # Need to track session state

    def correlate(
        self,
        entries: Iterator[LogEntry] | list[LogEntry],
        buffer_size: int = 10000
    ) -> Iterator[CorrelationGroup]:
        """
        Group entries by session.

        Args:
            entries: Log entries to correlate
            buffer_size: Maximum entries to buffer

        Yields:
            CorrelationGroup for each session
        """
        # Track sessions: session_key -> (entries, last_timestamp)
        sessions: dict[str, tuple[list[LogEntry], datetime | None]] = defaultdict(
            lambda: ([], None)
        )

        for entry in entries:
            session_key = self._extract_session_key(entry)
            if not session_key:
                continue

            # H3: Limit session group count to prevent memory exhaustion
            if session_key not in sessions and len(sessions) >= self.max_sessions:
                if not self._session_overflow_warned:
                    warnings.warn(
                        f"Session group limit ({self.max_sessions}) exceeded. "
                        "Additional sessions will be dropped.",
                        UserWarning,
                        stacklevel=2,
                    )
                    self._session_overflow_warned = True
                continue

            session_entries, last_ts = sessions[session_key]

            # Check for session timeout
            if (
                last_ts and
                entry.timestamp and
                entry.timestamp - last_ts > self.session_timeout
            ):
                # Emit old session, start new
                if len(session_entries) >= 2:
                    yield self._create_group(session_key, session_entries)
                sessions[session_key] = ([entry], entry.timestamp)
            else:
                session_entries.append(entry)
                sessions[session_key] = (session_entries, entry.timestamp or last_ts)

        # Emit remaining sessions
        for session_key, (session_entries, _) in sessions.items():
            if len(session_entries) >= 2:
                yield self._create_group(session_key, session_entries)

    def _extract_session_key(self, entry: LogEntry) -> str | None:
        """Extract session identifier from entry."""
        # Check correlation (the correct field name)
        if entry.correlation:
            if entry.correlation.session_id:
                return f"session:{entry.correlation.session_id}"
            if entry.correlation.user_id:
                return f"user:{entry.correlation.user_id}"

        # Check structured data
        for field in self.session_fields:
            if field in entry.structured_data:
                return f"{field}:{entry.structured_data[field]}"

        return None

    def _create_group(
        self,
        session_key: str,
        entries: list[LogEntry]
    ) -> CorrelationGroup:
        """Create a session group."""
        timestamps = [e.timestamp for e in entries if e.timestamp]
        time_range = (min(timestamps), max(timestamps)) if timestamps else None
        sources = {e.source.file_path or "<unknown>" for e in entries}

        return CorrelationGroup(
            id=uuid4(),
            correlation_key=session_key,
            correlation_type="session",
            entries=entries,
            sources=sources,
            time_range=time_range,
        )
