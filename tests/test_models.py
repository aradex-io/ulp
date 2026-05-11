"""
Tests for core data models.
"""

import pytest
from datetime import datetime
from uuid import UUID

from ulp.core.models import (
    LogLevel,
    LogSource,
    NetworkInfo,
    HTTPInfo,
    CorrelationIds,
    LogEntry,
    ParseResult,
    FormatSignature,
)


class TestLogLevel:
    """Tests for LogLevel enum."""

    def test_from_string_standard_names(self):
        """Test parsing standard level names."""
        assert LogLevel.from_string("DEBUG") == LogLevel.DEBUG
        assert LogLevel.from_string("INFO") == LogLevel.INFO
        assert LogLevel.from_string("WARNING") == LogLevel.WARNING
        assert LogLevel.from_string("ERROR") == LogLevel.ERROR
        assert LogLevel.from_string("CRITICAL") == LogLevel.CRITICAL

    def test_from_string_lowercase(self):
        """Test parsing lowercase level names."""
        assert LogLevel.from_string("debug") == LogLevel.DEBUG
        assert LogLevel.from_string("info") == LogLevel.INFO
        assert LogLevel.from_string("warning") == LogLevel.WARNING
        assert LogLevel.from_string("error") == LogLevel.ERROR

    def test_from_string_aliases(self):
        """Test parsing level aliases."""
        assert LogLevel.from_string("warn") == LogLevel.WARNING
        assert LogLevel.from_string("err") == LogLevel.ERROR
        assert LogLevel.from_string("crit") == LogLevel.CRITICAL
        assert LogLevel.from_string("fatal") == LogLevel.CRITICAL
        assert LogLevel.from_string("emerg") == LogLevel.EMERGENCY

    def test_from_string_single_char(self):
        """Test parsing single character abbreviations."""
        assert LogLevel.from_string("D") == LogLevel.DEBUG
        assert LogLevel.from_string("I") == LogLevel.INFO
        assert LogLevel.from_string("W") == LogLevel.WARNING
        assert LogLevel.from_string("E") == LogLevel.ERROR

    def test_from_string_syslog_numeric(self):
        """Test parsing syslog numeric priorities."""
        assert LogLevel.from_string("0") == LogLevel.EMERGENCY
        assert LogLevel.from_string("3") == LogLevel.ERROR
        assert LogLevel.from_string("4") == LogLevel.WARNING
        assert LogLevel.from_string("6") == LogLevel.INFO
        assert LogLevel.from_string("7") == LogLevel.DEBUG

    def test_from_string_unknown(self):
        """Test parsing unknown level strings."""
        assert LogLevel.from_string("UNKNOWN") == LogLevel.UNKNOWN
        assert LogLevel.from_string("random") == LogLevel.UNKNOWN
        assert LogLevel.from_string("") == LogLevel.UNKNOWN

    def test_level_comparison(self):
        """Test level comparison operators."""
        assert LogLevel.ERROR > LogLevel.WARNING
        assert LogLevel.WARNING >= LogLevel.WARNING
        assert LogLevel.INFO < LogLevel.WARNING
        assert LogLevel.DEBUG <= LogLevel.INFO


class TestLogSource:
    """Tests for LogSource dataclass."""

    def test_default_values(self):
        """Test LogSource with default values."""
        source = LogSource()
        assert source.file_path is None
        assert source.line_number is None
        assert source.hostname is None
        assert source.service is None

    def test_with_values(self):
        """Test LogSource with specified values."""
        source = LogSource(
            file_path="/var/log/app.log",
            line_number=42,
            hostname="server1",
            service="myapp",
        )
        assert source.file_path == "/var/log/app.log"
        assert source.line_number == 42
        assert source.hostname == "server1"
        assert source.service == "myapp"

    def test_to_dict(self):
        """Test LogSource.to_dict() excludes None values."""
        source = LogSource(file_path="/var/log/app.log", hostname="server1")
        d = source.to_dict()

        assert d["file_path"] == "/var/log/app.log"
        assert d["hostname"] == "server1"
        assert "line_number" not in d
        assert "service" not in d


class TestHTTPInfo:
    """Tests for HTTPInfo dataclass."""

    def test_default_values(self):
        """Test HTTPInfo with default values."""
        http = HTTPInfo()
        assert http.method is None
        assert http.path is None
        assert http.status_code is None

    def test_with_values(self):
        """Test HTTPInfo with specified values."""
        http = HTTPInfo(
            method="GET",
            path="/api/users",
            status_code=200,
            response_size=1024,
        )
        assert http.method == "GET"
        assert http.path == "/api/users"
        assert http.status_code == 200
        assert http.response_size == 1024

    def test_to_dict(self):
        """Test HTTPInfo.to_dict() excludes None values."""
        http = HTTPInfo(method="GET", status_code=200)
        d = http.to_dict()

        assert d["method"] == "GET"
        assert d["status_code"] == 200
        assert "path" not in d


class TestLogEntry:
    """Tests for LogEntry dataclass."""

    def test_default_values(self):
        """Test LogEntry with default values."""
        entry = LogEntry()
        assert isinstance(entry.id, UUID)
        assert entry.raw == ""
        assert entry.timestamp is None
        assert entry.level == LogLevel.UNKNOWN
        assert entry.message == ""
        assert entry.source is not None
        assert entry.http is None
        assert entry.network is None

    def test_with_values(self):
        """Test LogEntry with specified values."""
        entry = LogEntry(
            timestamp=datetime(2026, 1, 27, 10, 15, 32),
            level=LogLevel.INFO,
            message="Test message",
            format_detected="json_structured",
        )
        assert entry.timestamp == datetime(2026, 1, 27, 10, 15, 32)
        assert entry.level == LogLevel.INFO
        assert entry.message == "Test message"
        assert entry.format_detected == "json_structured"

    def test_is_error(self):
        """Test LogEntry.is_error() method."""
        info_entry = LogEntry(level=LogLevel.INFO)
        assert not info_entry.is_error()

        warning_entry = LogEntry(level=LogLevel.WARNING)
        assert not warning_entry.is_error()

        error_entry = LogEntry(level=LogLevel.ERROR)
        assert error_entry.is_error()

        critical_entry = LogEntry(level=LogLevel.CRITICAL)
        assert critical_entry.is_error()

    def test_formatted_timestamp(self):
        """Test LogEntry.formatted_timestamp() method."""
        entry_with_ts = LogEntry(timestamp=datetime(2026, 1, 27, 10, 15, 32))
        assert entry_with_ts.formatted_timestamp() == "2026-01-27 10:15:32"
        assert entry_with_ts.formatted_timestamp("%H:%M:%S") == "10:15:32"

        entry_no_ts = LogEntry()
        assert entry_no_ts.formatted_timestamp() == "-"

    def test_to_dict(self):
        """Test LogEntry.to_dict() serialization."""
        entry = LogEntry(
            timestamp=datetime(2026, 1, 27, 10, 15, 32),
            level=LogLevel.INFO,
            message="Test message",
            format_detected="test",
            parser_name="test_parser",
        )
        d = entry.to_dict()

        assert d["timestamp"] == "2026-01-27T10:15:32"
        assert d["level"] == "INFO"
        assert d["message"] == "Test message"
        assert d["format_detected"] == "test"
        assert d["parser_name"] == "test_parser"
        assert "id" in d

    def test_from_dict(self):
        """Test LogEntry.from_dict() deserialization."""
        data = {
            "timestamp": "2026-01-27T10:15:32",
            "level": "INFO",
            "message": "Test message",
            "format_detected": "test",
            "source": {"file_path": "/var/log/test.log"},
        }
        entry = LogEntry.from_dict(data)

        assert entry.timestamp is not None
        assert entry.level == LogLevel.INFO
        assert entry.message == "Test message"
        assert entry.source.file_path == "/var/log/test.log"


class TestParseResult:
    """Tests for ParseResult dataclass."""

    def test_empty_result(self):
        """Test ParseResult with no entries."""
        result = ParseResult(entries=[])
        assert result.entry_count == 0
        assert result.error_count == 0

    def test_with_entries(self):
        """Test ParseResult with entries."""
        entries = [
            LogEntry(level=LogLevel.INFO, message="msg1"),
            LogEntry(level=LogLevel.ERROR, message="msg2"),
            LogEntry(level=LogLevel.INFO, message="msg3", parse_errors=["error"]),
        ]
        result = ParseResult(
            entries=entries,
            format_detected="test",
            confidence=0.95,
        )

        assert result.entry_count == 3
        assert result.error_count == 1
        assert result.format_detected == "test"
        assert result.confidence == 0.95

    def test_filter(self):
        """Test ParseResult.filter() method."""
        entries = [
            LogEntry(level=LogLevel.INFO),
            LogEntry(level=LogLevel.WARNING),
            LogEntry(level=LogLevel.ERROR),
        ]
        result = ParseResult(entries=entries)

        filtered = result.filter(level=LogLevel.WARNING)
        assert len(filtered.entries) == 2  # WARNING and ERROR


class TestFormatSignature:
    """Tests for FormatSignature dataclass."""

    def test_basic_signature(self):
        """Test creating a basic format signature."""
        sig = FormatSignature(
            name="test_format",
            description="Test format",
            magic_patterns=[r"^TEST:"],
            weight=1.0,
        )
        assert sig.name == "test_format"
        assert sig.description == "Test format"
        assert len(sig.magic_patterns) == 1
        assert sig.is_json is False
        assert sig.weight == 1.0
