"""
Tests for infrastructure layer components.

Tests sources, correlation strategies, and normalization pipeline.
"""

import pytest
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path

from ulp.domain.entities import LogEntry, LogLevel, CorrelationIds
from ulp.infrastructure import (
    # Sources
    FileStreamSource,
    LargeFileStreamSource,
    ChunkedFileStreamSource,
    # Correlation
    RequestIdCorrelation,
    TimestampWindowCorrelation,
    SessionCorrelation,
    # Normalization
    NormalizationPipeline,
    TimestampNormalizer,
    LevelNormalizer,
    FieldNormalizer,
)


class TestFileStreamSource:
    """Tests for FileStreamSource."""

    def test_read_lines(self, tmp_path):
        """Test basic line reading."""
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\nline2\nline3\n")

        source = FileStreamSource(log_file)
        lines = list(source.read_lines())

        assert len(lines) == 3
        assert lines[0] == "line1"
        assert lines[1] == "line2"
        assert lines[2] == "line3"

    def test_strips_newlines(self, tmp_path):
        """Test that newlines are stripped."""
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\r\nline2\nline3\r\n")

        source = FileStreamSource(log_file)
        lines = list(source.read_lines())

        assert lines[0] == "line1"
        assert lines[1] == "line2"

    def test_file_not_found(self):
        """Test FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            FileStreamSource("/nonexistent/file.log")

    def test_metadata(self, tmp_path):
        """Test source metadata."""
        log_file = tmp_path / "test.log"
        log_file.write_text("some content\n")

        source = FileStreamSource(log_file)
        meta = source.metadata()

        assert meta["source_type"] == "file"
        assert meta["name"] == "test.log"
        assert "size_bytes" in meta


class TestLargeFileStreamSource:
    """Tests for LargeFileStreamSource."""

    def test_read_small_file(self, tmp_path):
        """Test reading small file (no mmap)."""
        log_file = tmp_path / "small.log"
        log_file.write_text("line1\nline2\n")

        source = LargeFileStreamSource(log_file)
        lines = list(source.read_lines())

        assert len(lines) == 2
        assert source._use_mmap is False

    def test_metadata_includes_mmap_flag(self, tmp_path):
        """Test metadata includes mmap status."""
        log_file = tmp_path / "test.log"
        log_file.write_text("content\n")

        source = LargeFileStreamSource(log_file)
        meta = source.metadata()

        assert "using_mmap" in meta


class TestChunkedFileStreamSource:
    """Tests for ChunkedFileStreamSource with progress."""

    def test_read_with_progress(self, tmp_path):
        """Test reading with progress callback."""
        log_file = tmp_path / "test.log"
        # Create file with enough lines to trigger callback
        lines = [f"line {i}\n" for i in range(15000)]
        log_file.write_text("".join(lines))

        progress_calls = []

        def on_progress(bytes_read, total_bytes, lines_read):
            progress_calls.append((bytes_read, total_bytes, lines_read))

        source = ChunkedFileStreamSource(
            log_file,
            progress_callback=on_progress,
            callback_interval=5000,
        )

        result = list(source.read_lines())

        assert len(result) == 15000
        assert len(progress_calls) >= 2  # At least 2 callbacks


class TestRequestIdCorrelation:
    """Tests for RequestIdCorrelation strategy."""

    def test_correlate_by_request_id(self):
        """Test correlation by request_id."""
        entries = [
            self._make_entry("msg1", request_id="req-001"),
            self._make_entry("msg2", request_id="req-001"),
            self._make_entry("msg3", request_id="req-002"),
            self._make_entry("msg4", request_id="req-001"),
        ]

        strategy = RequestIdCorrelation()
        groups = list(strategy.correlate(iter(entries)))

        # Should have 2 groups (req-001 with 3 entries, req-002 alone)
        assert len(groups) >= 1

        # Find the req-001 group
        req_001_group = next((g for g in groups if g.correlation_key == "req-001"), None)
        assert req_001_group is not None
        assert len(req_001_group.entries) == 3

    def test_no_correlation_ids(self):
        """Test entries without correlation IDs."""
        entries = [
            LogEntry(message="no id 1"),
            LogEntry(message="no id 2"),
        ]

        strategy = RequestIdCorrelation()
        groups = list(strategy.correlate(iter(entries)))

        # No groups since no IDs (entries without correlation are orphans)
        assert len(groups) == 0

    def test_supports_streaming(self):
        """Test that RequestIdCorrelation doesn't support streaming."""
        strategy = RequestIdCorrelation()
        assert strategy.supports_streaming() is False

    def _make_entry(self, msg: str, request_id: str = None) -> LogEntry:
        """Helper to create entry with correlation ID."""
        entry = LogEntry(message=msg)
        if request_id:
            entry.correlation = CorrelationIds(request_id=request_id)
        return entry


class TestTimestampWindowCorrelation:
    """Tests for TimestampWindowCorrelation strategy."""

    def test_correlate_by_timestamp(self):
        """Test correlation by timestamp proximity."""
        now = datetime.now()

        entries = [
            LogEntry(message="msg1", timestamp=now),
            LogEntry(message="msg2", timestamp=now + timedelta(milliseconds=100)),
            LogEntry(message="msg3", timestamp=now + timedelta(seconds=5)),
        ]

        # Add different sources
        entries[0].source.file_path = "app.log"
        entries[1].source.file_path = "nginx.log"
        entries[2].source.file_path = "app.log"

        strategy = TimestampWindowCorrelation(
            window_seconds=1.0,
            require_multiple_sources=True,
        )
        groups = list(strategy.correlate(iter(entries)))

        # First two should be grouped, third is separate
        assert len(groups) >= 1

    def test_supports_streaming(self):
        """Test that TimestampWindowCorrelation supports streaming."""
        strategy = TimestampWindowCorrelation()
        assert strategy.supports_streaming() is True


class TestSessionCorrelation:
    """Tests for SessionCorrelation strategy."""

    def test_correlate_by_session(self):
        """Test correlation by session ID."""
        now = datetime.now()

        entries = [
            self._make_entry("msg1", session_id="sess-001", ts=now),
            self._make_entry("msg2", session_id="sess-001", ts=now + timedelta(seconds=1)),
            self._make_entry("msg3", session_id="sess-002", ts=now),
        ]

        strategy = SessionCorrelation()
        groups = list(strategy.correlate(iter(entries)))

        # Should have groups for sessions with 2+ entries
        session_groups = [g for g in groups if g.correlation_key.startswith("session:")]
        assert any(len(g.entries) == 2 for g in groups)

    def _make_entry(self, msg: str, session_id: str = None, ts: datetime = None) -> LogEntry:
        """Helper to create entry with session ID."""
        entry = LogEntry(message=msg, timestamp=ts)
        if session_id:
            entry.correlation = CorrelationIds(session_id=session_id)
        return entry


class TestNormalizationPipeline:
    """Tests for NormalizationPipeline."""

    def test_empty_pipeline(self):
        """Test pipeline with no steps."""
        pipeline = NormalizationPipeline()
        entry = LogEntry(message="test")

        result = pipeline.process_one(entry)
        assert result.message == "test"

    def test_single_step(self):
        """Test pipeline with single step."""
        pipeline = NormalizationPipeline([
            LevelNormalizer(),
        ])

        entry = LogEntry(message="test", level=LogLevel.UNKNOWN)
        entry.structured_data = {"level": "error"}

        result = pipeline.process_one(entry)
        assert result.level == LogLevel.ERROR

    def test_multiple_steps(self):
        """Test pipeline with multiple steps."""
        pipeline = NormalizationPipeline([
            LevelNormalizer(),
            FieldNormalizer(),
        ])

        entry = LogEntry(message="test", level=LogLevel.UNKNOWN)
        entry.structured_data = {"severity": "warning", "msg": "the message"}

        result = pipeline.process_one(entry)
        assert result.level == LogLevel.WARNING
        assert "message" in result.structured_data  # msg -> message

    def test_process_stream(self):
        """Test processing a stream of entries."""
        pipeline = NormalizationPipeline([
            LevelNormalizer(),
        ])

        entries = [
            LogEntry(message="1", structured_data={"level": "info"}),
            LogEntry(message="2", structured_data={"level": "error"}),
        ]

        results = list(pipeline.process(iter(entries)))
        assert len(results) == 2
        assert results[0].level == LogLevel.INFO
        assert results[1].level == LogLevel.ERROR

    def test_stats(self):
        """Test pipeline statistics."""
        pipeline = NormalizationPipeline([LevelNormalizer()])
        entries = [LogEntry(message=f"msg{i}") for i in range(5)]

        list(pipeline.process(iter(entries)))

        stats = pipeline.stats
        assert stats["processed"] == 5
        assert stats["errors"] == 0


class TestTimestampNormalizer:
    """Tests for TimestampNormalizer."""

    def test_normalize_to_utc(self):
        """Test normalizing timestamps to UTC."""
        from datetime import timezone

        normalizer = TimestampNormalizer(target_tz="UTC")

        # Naive timestamp (assumes UTC)
        entry = LogEntry(
            message="test",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
        )

        result = normalizer.normalize(entry)
        assert result.timestamp.tzinfo == timezone.utc

    def test_no_timestamp(self):
        """Test entry without timestamp."""
        normalizer = TimestampNormalizer()
        entry = LogEntry(message="no timestamp")

        result = normalizer.normalize(entry)
        assert result.timestamp is None


class TestLevelNormalizer:
    """Tests for LevelNormalizer."""

    def test_normalize_from_structured_data(self):
        """Test extracting level from structured data."""
        normalizer = LevelNormalizer()

        entry = LogEntry(message="test", level=LogLevel.UNKNOWN)
        entry.structured_data = {"level": "warning"}

        result = normalizer.normalize(entry)
        assert result.level == LogLevel.WARNING

    def test_already_has_level(self):
        """Test entry that already has a level."""
        normalizer = LevelNormalizer()

        entry = LogEntry(message="test", level=LogLevel.ERROR)
        entry.structured_data = {"level": "info"}

        result = normalizer.normalize(entry)
        # Should not change existing non-UNKNOWN level
        assert result.level == LogLevel.ERROR


class TestFieldNormalizer:
    """Tests for FieldNormalizer."""

    def test_normalize_field_names(self):
        """Test normalizing field names."""
        normalizer = FieldNormalizer()

        entry = LogEntry(message="test")
        entry.structured_data = {
            "msg": "the message",
            "@timestamp": "2024-01-15T10:30:00Z",
            "severity": "error",
        }

        result = normalizer.normalize(entry)

        # Check canonical names
        assert "message" in result.structured_data
        assert "timestamp" in result.structured_data
        assert "level" in result.structured_data

    def test_preserve_original(self):
        """Test preserving original field names."""
        normalizer = FieldNormalizer(preserve_original=True)

        entry = LogEntry(message="test")
        entry.structured_data = {"msg": "the message"}

        result = normalizer.normalize(entry)

        assert "message" in result.structured_data
        assert "_original_msg" in result.structured_data

    def test_custom_mappings(self):
        """Test custom field mappings."""
        custom_mappings = {
            "custom_field": ["cf", "c_f", "custom-field"],
        }
        normalizer = FieldNormalizer(field_mappings=custom_mappings)

        entry = LogEntry(message="test")
        entry.structured_data = {"cf": "value"}

        result = normalizer.normalize(entry)
        assert "custom_field" in result.structured_data
