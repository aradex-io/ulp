"""
Tests for format detection engine.
"""

import pytest

from ulp.detection.detector import FormatDetector
from ulp.detection.signatures import BUILTIN_SIGNATURES


class TestFormatDetector:
    """Tests for FormatDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a FormatDetector instance."""
        return FormatDetector()

    def test_detect_json_structured(self, detector, sample_json_logs):
        """Test detection of JSON structured logs."""
        fmt, confidence = detector.detect(sample_json_logs)
        assert fmt == "json_structured"
        assert confidence > 0.7

    def test_detect_apache_combined(self, detector, sample_apache_combined_logs):
        """Test detection of Apache Combined logs."""
        fmt, confidence = detector.detect(sample_apache_combined_logs)
        assert fmt in ["apache_combined", "nginx_access"]  # Very similar formats
        assert confidence > 0.7

    def test_detect_apache_common(self, detector, sample_apache_common_logs):
        """Test detection of Apache Common logs."""
        fmt, confidence = detector.detect(sample_apache_common_logs)
        assert fmt in ["apache_common", "apache_combined", "nginx_access"]
        assert confidence > 0.5

    def test_detect_nginx_error(self, detector, sample_nginx_error_logs):
        """Test detection of Nginx error logs."""
        fmt, confidence = detector.detect(sample_nginx_error_logs)
        assert fmt == "nginx_error"
        assert confidence > 0.8

    def test_detect_syslog_rfc3164(self, detector, sample_syslog_rfc3164_logs):
        """Test detection of RFC 3164 syslog."""
        fmt, confidence = detector.detect(sample_syslog_rfc3164_logs)
        assert fmt == "syslog_rfc3164"
        assert confidence > 0.5

    def test_detect_syslog_rfc5424(self, detector, sample_syslog_rfc5424_logs):
        """Test detection of RFC 5424 syslog."""
        fmt, confidence = detector.detect(sample_syslog_rfc5424_logs)
        assert fmt == "syslog_rfc5424"
        assert confidence > 0.8

    def test_detect_python_logging(self, detector, sample_python_logs):
        """Test detection of Python logging format."""
        fmt, confidence = detector.detect(sample_python_logs)
        assert fmt == "python_logging"
        assert confidence > 0.7

    def test_detect_empty_input(self, detector):
        """Test detection with empty input."""
        fmt, confidence = detector.detect([])
        assert fmt == "unknown"
        assert confidence == 0.0

    def test_detect_single_line(self, detector):
        """Test detection with single line."""
        fmt, confidence = detector.detect(['{"level": "INFO", "message": "test"}'])
        assert fmt == "json_structured"
        assert confidence > 0.5

    def test_detect_all(self, detector, sample_json_logs):
        """Test detect_all returns ranked list."""
        results = detector.detect_all(sample_json_logs)
        assert len(results) > 0
        assert results[0][0] == "json_structured"
        # Results should be sorted by confidence (descending)
        confidences = [r[1] for r in results]
        assert confidences == sorted(confidences, reverse=True)

    def test_detect_file(self, detector, temp_log_file):
        """Test detection from file."""
        fmt, confidence = detector.detect_file(str(temp_log_file))
        assert fmt in ["apache_combined", "nginx_access"]
        assert confidence > 0.5

    def test_detect_file_not_found(self, detector):
        """Test detection with non-existent file."""
        fmt, confidence = detector.detect_file("/nonexistent/path/file.log")
        assert fmt == "unknown"
        assert confidence == 0.0

    def test_custom_signatures(self):
        """Test detector with custom signatures."""
        from ulp.core.models import FormatSignature

        custom_sig = FormatSignature(
            name="custom_format",
            description="Custom test format",
            magic_patterns=[r"^CUSTOM:"],
            weight=2.0,
        )

        detector = FormatDetector(signatures=[custom_sig])
        sample = ["CUSTOM: log message 1", "CUSTOM: log message 2"]

        fmt, confidence = detector.detect(sample)
        assert fmt == "custom_format"
        assert confidence > 0.5


class TestBuiltinSignatures:
    """Tests for built-in format signatures."""

    def test_all_signatures_have_required_fields(self):
        """Test that all signatures have required fields."""
        for sig in BUILTIN_SIGNATURES:
            assert sig.name, f"Signature missing name"
            assert sig.description, f"Signature {sig.name} missing description"
            assert sig.weight > 0, f"Signature {sig.name} has invalid weight"

    def test_no_duplicate_names(self):
        """Test that all signature names are unique."""
        names = [sig.name for sig in BUILTIN_SIGNATURES]
        assert len(names) == len(set(names)), "Duplicate signature names found"

    def test_json_signature_is_json(self):
        """Test that JSON signature has is_json flag."""
        json_sigs = [s for s in BUILTIN_SIGNATURES if "json" in s.name.lower()]
        for sig in json_sigs:
            assert sig.is_json, f"JSON signature {sig.name} should have is_json=True"
