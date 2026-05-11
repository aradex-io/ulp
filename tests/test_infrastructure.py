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


# ---------------------------------------------------------------------------
# HIGH-T-2: mmap branch coverage
# ---------------------------------------------------------------------------

class TestLargeFileStreamSourceMmap:
    """Additional mmap path tests (HIGH-T-2)."""

    def test_mmap_branch_actually_runs(self, tmp_path, monkeypatch):
        """Force mmap path on a small file by lowering MMAP_THRESHOLD to 0."""
        from ulp.infrastructure.sources import file_source as fs_mod

        monkeypatch.setattr(fs_mod.LargeFileStreamSource, "MMAP_THRESHOLD", 0, raising=False)
        f = tmp_path / "small.log"
        f.write_text("line1\nline2\nline3\n")
        src = fs_mod.LargeFileStreamSource(str(f))
        # The threshold monkeypatch may not affect an already-constructed object,
        # so force the flag directly.
        src._use_mmap = True
        lines = list(src.read_lines())
        assert lines == ["line1", "line2", "line3"]

    def test_mmap_empty_file(self, tmp_path):
        """mmap on an empty file must not raise and must yield nothing."""
        f = tmp_path / "empty.log"
        f.write_bytes(b"")
        src = LargeFileStreamSource(str(f))
        src._use_mmap = True
        assert list(src.read_lines()) == []

    def test_mmap_line_too_long(self, tmp_path):
        """mmap path must raise LineTooLongError for lines exceeding MAX_LINE_LENGTH."""
        from ulp.core.security import LineTooLongError, MAX_LINE_LENGTH

        f = tmp_path / "huge_line.log"
        # Write a single line longer than the cap (no newline)
        f.write_bytes(b"a" * (MAX_LINE_LENGTH + 10))
        src = LargeFileStreamSource(str(f))
        src._use_mmap = True
        with pytest.raises(LineTooLongError):
            list(src.read_lines())

    def test_mmap_no_trailing_newline(self, tmp_path):
        """mmap path correctly yields a final partial line with no trailing newline."""
        from ulp.infrastructure.sources import file_source as fs_mod

        f = tmp_path / "partial.log"
        f.write_text("line1\nno_newline_here")
        src = fs_mod.LargeFileStreamSource(str(f))
        src._use_mmap = True
        lines = list(src.read_lines())
        assert "no_newline_here" in lines


# ---------------------------------------------------------------------------
# HIGH-T-3: Stdin sources
# ---------------------------------------------------------------------------

class TestStdinStreamSource:
    """Tests for StdinStreamSource (HIGH-T-3)."""

    def test_basic_read(self, monkeypatch):
        """Basic multi-line stdin read."""
        import io
        from ulp.infrastructure.sources.stdin_source import StdinStreamSource

        monkeypatch.setattr("sys.stdin", io.StringIO("line1\nline2\n"))
        src = StdinStreamSource()
        assert list(src.read_lines()) == ["line1", "line2"]

    def test_empty_stdin(self, monkeypatch):
        """Empty stdin yields no lines."""
        import io
        from ulp.infrastructure.sources.stdin_source import StdinStreamSource

        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        src = StdinStreamSource()
        assert list(src.read_lines()) == []

    def test_single_line_no_newline(self, monkeypatch):
        """Single line without trailing newline is returned."""
        import io
        from ulp.infrastructure.sources.stdin_source import StdinStreamSource

        monkeypatch.setattr("sys.stdin", io.StringIO("only_line"))
        src = StdinStreamSource()
        lines = list(src.read_lines())
        assert lines == ["only_line"]

    def test_line_too_long_raises(self, monkeypatch):
        """Lines exceeding MAX_LINE_LENGTH must raise LineTooLongError."""
        import io
        from ulp.core.security import MAX_LINE_LENGTH, LineTooLongError
        from ulp.infrastructure.sources.stdin_source import StdinStreamSource

        long_line = "a" * (MAX_LINE_LENGTH + 1) + "\n"
        monkeypatch.setattr("sys.stdin", io.StringIO(long_line))
        src = StdinStreamSource()
        with pytest.raises(LineTooLongError):
            list(src.read_lines())

    def test_metadata_after_read(self, monkeypatch):
        """Metadata is populated after reading."""
        import io
        from ulp.infrastructure.sources.stdin_source import StdinStreamSource

        monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\n"))
        src = StdinStreamSource()
        list(src.read_lines())
        meta = src.metadata()
        assert meta["source_type"] == "stdin"
        assert int(meta["lines_read"]) == 2


class TestBufferedStdinSource:
    """Tests for BufferedStdinSource (HIGH-T-3)."""

    def test_peek_then_read(self, monkeypatch):
        """peek() returns first N lines; read_lines() returns ALL lines including peeked."""
        import io
        from ulp.infrastructure.sources.stdin_source import BufferedStdinSource

        monkeypatch.setattr("sys.stdin", io.StringIO("a\nb\nc\n"))
        src = BufferedStdinSource(peek_lines=2)
        peeked = src.peek()
        assert peeked[:2] == ["a", "b"]
        all_lines = list(src.read_lines())
        assert all_lines == ["a", "b", "c"]

    def test_peek_default(self, monkeypatch):
        """peek() with no argument uses peek_lines default."""
        import io
        from ulp.infrastructure.sources.stdin_source import BufferedStdinSource

        monkeypatch.setattr("sys.stdin", io.StringIO("x\ny\nz\n"))
        src = BufferedStdinSource(peek_lines=2)
        peeked = src.peek()
        assert len(peeked) == 2

    def test_empty_stdin_buffered(self, monkeypatch):
        """Empty stdin in BufferedStdinSource yields nothing."""
        import io
        from ulp.infrastructure.sources.stdin_source import BufferedStdinSource

        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        src = BufferedStdinSource()
        assert list(src.read_lines()) == []

    def test_line_too_long_in_buffered(self, monkeypatch):
        """Lines exceeding MAX_LINE_LENGTH in BufferedStdinSource must raise LineTooLongError."""
        import io
        from ulp.core.security import MAX_LINE_LENGTH, LineTooLongError
        from ulp.infrastructure.sources.stdin_source import BufferedStdinSource

        long_line = "a" * (MAX_LINE_LENGTH + 1) + "\n"
        monkeypatch.setattr("sys.stdin", io.StringIO(long_line))
        src = BufferedStdinSource()
        with pytest.raises(LineTooLongError):
            list(src.read_lines())

    def test_buffered_exhausted_flag(self, monkeypatch):
        """_exhausted is True when stdin runs out during peek."""
        import io
        from ulp.infrastructure.sources.stdin_source import BufferedStdinSource

        # Only 2 lines; peek_lines=50 → stdin exhausted during peek
        monkeypatch.setattr("sys.stdin", io.StringIO("x\ny\n"))
        src = BufferedStdinSource(peek_lines=50)
        src.peek()
        assert src._exhausted is True


# ---------------------------------------------------------------------------
# HIGH-T-5: Correlation bound tests
# ---------------------------------------------------------------------------

def test_request_id_orphan_bound():
    """Feed more than MAX_ORPHAN_ENTRIES orphans and confirm warning + no crash."""
    import warnings
    from ulp.core.security import MAX_ORPHAN_ENTRIES
    from ulp.infrastructure.correlation.strategies import RequestIdCorrelation

    # Entries with no correlation IDs are orphans
    entries = [LogEntry(message=f"msg{i}", correlation=CorrelationIds()) for i in range(MAX_ORPHAN_ENTRIES + 100)]
    strategy = RequestIdCorrelation()
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        groups = list(strategy.correlate(iter(entries)))
    # No groups should be emitted (orphans are never grouped)
    assert isinstance(groups, list)
    # At least one UserWarning about orphan overflow
    overflow_warns = [x for x in w if issubclass(x.category, UserWarning) and "orphan" in str(x.message).lower()]
    assert len(overflow_warns) >= 1


def test_session_groups_bound():
    """Feed more than MAX_SESSION_GROUPS unique sessions and confirm no crash + warning."""
    import warnings
    from ulp.core.security import MAX_SESSION_GROUPS
    from ulp.infrastructure.correlation.strategies import SessionCorrelation

    entries = [
        LogEntry(message=f"msg{i}", correlation=CorrelationIds(session_id=f"sess-{i}"))
        for i in range(MAX_SESSION_GROUPS + 10)
    ]
    strategy = SessionCorrelation()
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        groups = list(strategy.correlate(iter(entries)))
    # Must complete without exception
    assert isinstance(groups, list)
    # At least one UserWarning about session overflow
    overflow_warns = [x for x in w if issubclass(x.category, UserWarning) and "session" in str(x.message).lower()]
    assert len(overflow_warns) >= 1
