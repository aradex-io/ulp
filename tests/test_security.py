"""
Tests for security features and remediations.
"""

import pytest
import warnings
from io import StringIO

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


class TestLineLengthValidation:
    """Tests for H1: Line length limits."""

    def test_valid_line_passes(self):
        """Normal lines should pass validation."""
        line = "This is a normal log line"
        result = validate_line_length(line)
        assert result == line

    def test_line_at_limit_passes(self):
        """Line exactly at limit should pass."""
        line = "x" * MAX_LINE_LENGTH
        result = validate_line_length(line)
        assert result == line

    def test_line_over_limit_raises(self):
        """Line over limit should raise LineTooLongError."""
        line = "x" * (MAX_LINE_LENGTH + 1)
        with pytest.raises(LineTooLongError) as exc_info:
            validate_line_length(line)

        assert "exceeds maximum" in str(exc_info.value)
        assert "split" in str(exc_info.value).lower()

    def test_custom_limit(self):
        """Custom limit should be respected."""
        line = "x" * 100

        # Should pass with higher limit
        validate_line_length(line, max_length=200)

        # Should fail with lower limit
        with pytest.raises(LineTooLongError):
            validate_line_length(line, max_length=50)


class TestJsonDepthValidation:
    """Tests for H4: JSON depth limits."""

    def test_shallow_json_passes(self):
        """Shallow JSON should pass validation."""
        data = {"level": "INFO", "message": "test"}
        assert validate_json_depth(data) is True

    def test_nested_json_within_limit(self):
        """Nested JSON within limit should pass."""
        data = {"a": {"b": {"c": {"d": "value"}}}}
        assert validate_json_depth(data, max_depth=10) is True

    def test_deeply_nested_json_raises(self):
        """Deeply nested JSON should raise error."""
        # Create deeply nested dict
        data = {"value": "leaf"}
        for i in range(60):
            data = {"nested": data}

        with pytest.raises(SecurityValidationError) as exc_info:
            validate_json_depth(data, max_depth=50)

        assert exc_info.value.validation_type == "json_depth"

    def test_nested_list_checked(self):
        """Lists should also be depth-checked."""
        # Build deeply nested list
        data = ["deep"]
        for _ in range(10):
            data = [data]

        with pytest.raises(SecurityValidationError):
            validate_json_depth(data, max_depth=5)


class TestRegexValidation:
    """Tests for M2: Regex pattern validation."""

    def test_valid_pattern_compiles(self):
        """Valid regex should compile."""
        pattern = validate_regex_pattern(r"error|warning")
        assert pattern.search("this is an error")

    def test_invalid_syntax_raises(self):
        """Invalid regex syntax should raise error."""
        with pytest.raises(SecurityValidationError) as exc_info:
            validate_regex_pattern(r"[unclosed")

        assert exc_info.value.validation_type == "regex_syntax"

    def test_too_long_pattern_raises(self):
        """Overly long pattern should raise error."""
        pattern = "a" * 1500

        with pytest.raises(SecurityValidationError) as exc_info:
            validate_regex_pattern(pattern, max_length=1000)

        assert exc_info.value.validation_type == "regex_length"

    def test_dangerous_nested_quantifier_detected(self):
        """Dangerous ReDoS patterns should be detected."""
        # Classic ReDoS pattern
        with pytest.raises(SecurityValidationError) as exc_info:
            validate_regex_pattern(r"(a+)+b")

        assert exc_info.value.validation_type == "regex_redos"

    def test_safe_pattern_allowed(self):
        """Safe patterns with quantifiers should be allowed."""
        # These are safe quantifier patterns
        pattern = validate_regex_pattern(r"\d{4}-\d{2}-\d{2}")
        assert pattern is not None


class TestCsvSanitization:
    """Tests for M4: CSV injection prevention."""

    def test_normal_text_unchanged(self):
        """Normal text should pass through unchanged."""
        assert sanitize_csv_cell("Hello world") == "Hello world"

    def test_equals_prefix_escaped(self):
        """Formula starting with = should be escaped."""
        assert sanitize_csv_cell("=SUM(A1:A10)") == "'=SUM(A1:A10)"

    def test_plus_prefix_escaped(self):
        """Formula starting with + should be escaped."""
        assert sanitize_csv_cell("+1234567890") == "'+1234567890"

    def test_minus_prefix_escaped(self):
        """Formula starting with - should be escaped."""
        assert sanitize_csv_cell("-1234567890") == "'-1234567890"

    def test_at_prefix_escaped(self):
        """Formula starting with @ should be escaped."""
        assert sanitize_csv_cell("@SUM(A1)") == "'@SUM(A1)"

    def test_tab_prefix_escaped(self):
        """Tab at start should be escaped."""
        assert sanitize_csv_cell("\tdata") == "'\tdata"

    def test_empty_string_unchanged(self):
        """Empty string should pass through."""
        assert sanitize_csv_cell("") == ""


class TestSymlinkHandling:
    """Tests for M6: Symlink detection."""

    def test_regular_file_not_symlink(self, tmp_path):
        """Regular file should not be detected as symlink."""
        regular_file = tmp_path / "regular.txt"
        regular_file.write_text("content")

        is_symlink, resolved = check_symlink(regular_file, warn=False)
        assert is_symlink is False
        assert resolved == regular_file

    def test_symlink_detected(self, tmp_path):
        """Symlink should be detected and resolved."""
        target = tmp_path / "target.txt"
        target.write_text("content")

        link = tmp_path / "link.txt"
        link.symlink_to(target)

        is_symlink, resolved = check_symlink(link, warn=False)
        assert is_symlink is True
        assert resolved == target

    def test_symlink_warning_emitted(self, tmp_path):
        """Warning should be emitted when following symlink."""
        target = tmp_path / "target.txt"
        target.write_text("content")

        link = tmp_path / "link.txt"
        link.symlink_to(target)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            check_symlink(link, warn=True)

            assert len(w) == 1
            assert "symlink" in str(w[0].message).lower()


class TestSecurityIntegration:
    """Integration tests for security features."""

    def test_json_parser_rejects_deep_json(self):
        """JSON parser should reject deeply nested JSON."""
        from ulp.parsers.json_parser import JSONParser

        # Create deeply nested JSON string
        deep_json = '{"a":' * 60 + '"value"' + '}' * 60

        parser = JSONParser()
        entry = parser.parse_line(deep_json)

        # Should have security error
        assert len(entry.parse_errors) > 0
        assert "security" in entry.parse_errors[0].lower() or "depth" in entry.parse_errors[0].lower()

    def test_file_source_validates_lines(self, tmp_path):
        """File source should validate line lengths."""
        from ulp.infrastructure.sources.file_source import FileStreamSource

        # Create file with normal lines
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\nline2\nline3\n")

        source = FileStreamSource(log_file)
        lines = list(source.read_lines())

        assert len(lines) == 3
        assert lines[0] == "line1"

    def test_csv_output_sanitizes_formulas(self, tmp_path):
        """CSV output should sanitize formula injections."""
        from ulp.cli.output import render_csv
        from ulp.core.models import LogEntry, LogSource, LogLevel

        # Create entry with formula-like message
        entry = LogEntry(
            message="=HYPERLINK('http://evil.com')",
            level=LogLevel.ERROR,
            source=LogSource(),
        )

        # Capture output
        import io
        import sys

        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()

        try:
            render_csv([entry])
            output = captured.getvalue()
        finally:
            sys.stdout = old_stdout

        # Formula should be escaped
        assert "'=" in output
