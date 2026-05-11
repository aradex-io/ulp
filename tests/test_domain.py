"""
Tests for domain layer entities and services.

Tests the clean architecture domain layer components.
"""

import pytest
from datetime import datetime, timedelta
from uuid import UUID

from ulp.domain.entities import (
    LogEntry,
    LogLevel,
    LogSource,
    CorrelationIds,
    CorrelationGroup,
    CorrelationResult,
)


class TestDomainLogLevel:
    """Tests for domain LogLevel enum."""

    def test_from_string_standard_names(self):
        """Test standard level names."""
        assert LogLevel.from_string("DEBUG") == LogLevel.DEBUG
        assert LogLevel.from_string("INFO") == LogLevel.INFO
        assert LogLevel.from_string("WARNING") == LogLevel.WARNING
        assert LogLevel.from_string("ERROR") == LogLevel.ERROR
        assert LogLevel.from_string("CRITICAL") == LogLevel.CRITICAL

    def test_from_string_lowercase(self):
        """Test lowercase level names."""
        assert LogLevel.from_string("debug") == LogLevel.DEBUG
        assert LogLevel.from_string("info") == LogLevel.INFO
        assert LogLevel.from_string("warning") == LogLevel.WARNING
        assert LogLevel.from_string("error") == LogLevel.ERROR

    def test_from_string_aliases(self):
        """Test level aliases."""
        assert LogLevel.from_string("warn") == LogLevel.WARNING
        assert LogLevel.from_string("err") == LogLevel.ERROR
        assert LogLevel.from_string("crit") == LogLevel.CRITICAL
        assert LogLevel.from_string("fatal") == LogLevel.CRITICAL
        assert LogLevel.from_string("emerg") == LogLevel.EMERGENCY

    def test_from_string_single_char(self):
        """Test single character abbreviations."""
        assert LogLevel.from_string("d") == LogLevel.DEBUG
        assert LogLevel.from_string("i") == LogLevel.INFO
        assert LogLevel.from_string("w") == LogLevel.WARNING
        assert LogLevel.from_string("e") == LogLevel.ERROR

    def test_level_comparison(self):
        """Test level ordering."""
        assert LogLevel.DEBUG < LogLevel.INFO
        assert LogLevel.INFO < LogLevel.WARNING
        assert LogLevel.WARNING < LogLevel.ERROR
        assert LogLevel.ERROR < LogLevel.CRITICAL
        assert LogLevel.ERROR >= LogLevel.WARNING
        assert LogLevel.ERROR <= LogLevel.CRITICAL


class TestDomainLogEntry:
    """Tests for domain LogEntry entity."""

    def test_default_values(self):
        """Test default initialization."""
        entry = LogEntry()
        assert entry.message == ""
        assert entry.level == LogLevel.UNKNOWN
        assert entry.timestamp is None
        assert entry.raw == ""

    def test_with_values(self):
        """Test initialization with values."""
        ts = datetime.now()
        entry = LogEntry(
            message="Test message",
            level=LogLevel.INFO,
            timestamp=ts,
            raw="raw line"
        )
        assert entry.message == "Test message"
        assert entry.level == LogLevel.INFO
        assert entry.timestamp == ts

    def test_is_error(self):
        """Test is_error property."""
        info_entry = LogEntry(level=LogLevel.INFO)
        assert not info_entry.is_error()

        error_entry = LogEntry(level=LogLevel.ERROR)
        assert error_entry.is_error()

        critical_entry = LogEntry(level=LogLevel.CRITICAL)
        assert critical_entry.is_error()

    def test_source_info(self):
        """Test source information."""
        entry = LogEntry()
        entry.source.file_path = "/var/log/test.log"
        entry.source.line_number = 42

        assert entry.source.file_path == "/var/log/test.log"
        assert entry.source.line_number == 42


class TestCorrelationIds:
    """Tests for CorrelationIds value object."""

    def test_default_empty(self):
        """Test default empty correlation IDs."""
        ids = CorrelationIds()
        assert ids.request_id is None
        assert ids.trace_id is None
        assert not ids.has_any_id()

    def test_has_any_id(self):
        """Test has_any_id method."""
        empty = CorrelationIds()
        assert not empty.has_any_id()

        with_request = CorrelationIds(request_id="req-123")
        assert with_request.has_any_id()

        with_trace = CorrelationIds(trace_id="trace-456")
        assert with_trace.has_any_id()

    def test_get_primary_id(self):
        """Test get_primary_id method returns (field_name, value) tuple."""
        empty = CorrelationIds()
        assert empty.get_primary_id() is None

        with_request = CorrelationIds(request_id="req-123")
        assert with_request.get_primary_id() == ("request_id", "req-123")

        # Request ID takes priority
        with_both = CorrelationIds(request_id="req-123", trace_id="trace-456")
        assert with_both.get_primary_id() == ("request_id", "req-123")


class TestCorrelationGroup:
    """Tests for CorrelationGroup entity."""

    def test_default_values(self):
        """Test default initialization."""
        group = CorrelationGroup()
        assert isinstance(group.id, UUID)
        assert group.correlation_key == ""
        assert group.correlation_type == ""
        assert len(group.entries) == 0
        assert len(group.sources) == 0

    def test_with_entries(self):
        """Test group with entries."""
        ts1 = datetime.now()
        ts2 = ts1 + timedelta(seconds=1)

        entry1 = LogEntry(message="First", timestamp=ts1)
        entry2 = LogEntry(message="Second", timestamp=ts2)

        group = CorrelationGroup(
            correlation_key="req-123",
            correlation_type="request_id",
            entries=[entry1, entry2],
            sources={"app.log", "nginx.log"},
        )

        assert group.correlation_key == "req-123"
        assert len(group.entries) == 2
        assert len(group.sources) == 2

    def test_timeline(self):
        """Test timeline method sorts entries."""
        ts1 = datetime.now()
        ts2 = ts1 + timedelta(seconds=1)
        ts3 = ts1 + timedelta(seconds=2)

        # Add entries out of order
        entry1 = LogEntry(message="Third", timestamp=ts3)
        entry2 = LogEntry(message="First", timestamp=ts1)
        entry3 = LogEntry(message="Second", timestamp=ts2)

        group = CorrelationGroup(entries=[entry1, entry2, entry3])
        timeline = group.timeline()

        assert len(timeline) == 3
        assert timeline[0].message == "First"
        assert timeline[1].message == "Second"
        assert timeline[2].message == "Third"


class TestCorrelationResult:
    """Tests for CorrelationResult entity."""

    def test_empty_result(self):
        """Test empty correlation result."""
        result = CorrelationResult()
        assert len(result.groups) == 0
        assert len(result.orphan_entries) == 0

    def test_with_groups(self):
        """Test result with groups and orphans."""
        group1 = CorrelationGroup(correlation_key="req-1")
        group2 = CorrelationGroup(correlation_key="req-2")
        orphan = LogEntry(message="Orphan entry")

        result = CorrelationResult(
            groups=[group1, group2],
            orphan_entries=[orphan],
        )

        assert len(result.groups) == 2
        assert len(result.orphan_entries) == 1

    def test_statistics(self):
        """Test statistics property computed on init."""
        entry1 = LogEntry(message="A")
        entry2 = LogEntry(message="B")
        group = CorrelationGroup(
            correlation_key="req-1",
            entries=[entry1, entry2],
        )
        orphan = LogEntry(message="Orphan")

        result = CorrelationResult(
            groups=[group],
            orphan_entries=[orphan],
        )

        stats = result.statistics
        assert stats["total_groups"] == 1
        assert stats["correlated_entries"] == 2
        assert stats["orphan_entries"] == 1
