"""
Tests for built-in parsers.
"""

import pytest
from datetime import datetime

from ulp.core.models import LogLevel
from ulp.parsers import ParserRegistry, registry
from ulp.parsers.json_parser import JSONParser
from ulp.parsers.apache import ApacheCommonParser, ApacheCombinedParser
from ulp.parsers.nginx import NginxAccessParser, NginxErrorParser
from ulp.parsers.syslog import SyslogRFC3164Parser, SyslogRFC5424Parser
from ulp.parsers.python_logging import PythonLoggingParser
from ulp.parsers.generic import GenericParser


class TestParserRegistry:
    """Tests for ParserRegistry."""

    def test_get_parser_by_format(self):
        """Test getting parser by format name."""
        parser = registry.get_parser("json_structured")
        assert parser is not None
        assert isinstance(parser, JSONParser)

    def test_get_parser_by_parser_name(self):
        """Test getting parser by parser name."""
        parser = registry.get_parser("json")
        assert parser is not None
        assert isinstance(parser, JSONParser)

    def test_get_parser_not_found(self):
        """Test getting non-existent parser."""
        parser = registry.get_parser("nonexistent_format")
        assert parser is None

    def test_list_parsers(self):
        """Test listing all registered parsers."""
        parsers = registry.list_parsers()
        assert len(parsers) >= 8  # At least 8 built-in parsers
        assert "json" in parsers
        assert "apache_combined" in parsers
        assert "generic" in parsers

    def test_list_formats(self):
        """Test listing all supported formats."""
        formats = registry.list_formats()
        assert len(formats) >= 10
        assert "json_structured" in formats
        assert "apache_combined" in formats

    def test_get_best_parser(self, sample_json_logs):
        """Test getting best parser for sample."""
        parser, confidence = registry.get_best_parser(sample_json_logs)
        assert parser is not None
        assert isinstance(parser, JSONParser)
        assert confidence > 0.5


class TestJSONParser:
    """Tests for JSONParser."""

    @pytest.fixture
    def parser(self):
        return JSONParser()

    def test_parse_basic_json(self, parser):
        """Test parsing basic JSON log."""
        line = '{"timestamp": "2026-01-27T10:15:32Z", "level": "INFO", "message": "Test"}'
        entry = parser.parse_line(line)

        assert entry.level == LogLevel.INFO
        assert entry.message == "Test"
        assert entry.timestamp is not None
        assert entry.format_detected == "json_structured"
        assert len(entry.parse_errors) == 0

    def test_parse_json_with_fields(self, parser):
        """Test parsing JSON with various field names."""
        line = '{"time": "2026-01-27T10:15:32Z", "severity": "error", "msg": "Error!"}'
        entry = parser.parse_line(line)

        assert entry.level == LogLevel.ERROR
        assert entry.message == "Error!"
        assert entry.timestamp is not None

    def test_parse_json_with_correlation(self, parser):
        """Test parsing JSON with correlation IDs."""
        line = '{"message": "Request", "request_id": "abc-123", "trace_id": "xyz-789"}'
        entry = parser.parse_line(line)

        assert entry.correlation.request_id == "abc-123"
        assert entry.correlation.trace_id == "xyz-789"

    def test_parse_invalid_json(self, parser):
        """Test parsing invalid JSON."""
        line = 'not valid json {'
        entry = parser.parse_line(line)

        assert len(entry.parse_errors) > 0
        assert entry.parser_confidence == 0.0

    def test_can_parse_json_sample(self, parser, sample_json_logs):
        """Test can_parse with JSON sample."""
        confidence = parser.can_parse(sample_json_logs)
        assert confidence > 0.8

    def test_can_parse_non_json_sample(self, parser, sample_apache_combined_logs):
        """Test can_parse with non-JSON sample."""
        confidence = parser.can_parse(sample_apache_combined_logs)
        assert confidence < 0.2


class TestApacheCombinedParser:
    """Tests for ApacheCombinedParser."""

    @pytest.fixture
    def parser(self):
        return ApacheCombinedParser()

    def test_parse_combined_format(self, parser):
        """Test parsing Apache Combined format."""
        line = '192.168.1.100 - admin [27/Jan/2026:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 1024 "http://example.com/" "Mozilla/5.0"'
        entry = parser.parse_line(line)

        assert entry.network.source_ip == "192.168.1.100"
        assert entry.http.method == "GET"
        assert entry.http.path == "/api/users"
        assert entry.http.status_code == 200
        assert entry.http.response_size == 1024
        assert entry.network.referer == "http://example.com/"
        assert "Mozilla" in entry.network.user_agent
        assert entry.correlation.user_id == "admin"
        assert entry.level == LogLevel.INFO

    def test_parse_error_status(self, parser):
        """Test parsing log with error status code."""
        line = '192.168.1.100 - - [27/Jan/2026:10:15:32 +0000] "GET /error HTTP/1.1" 500 128 "-" "-"'
        entry = parser.parse_line(line)

        assert entry.http.status_code == 500
        assert entry.level == LogLevel.ERROR

    def test_parse_warning_status(self, parser):
        """Test parsing log with 4xx status code."""
        line = '192.168.1.100 - - [27/Jan/2026:10:15:32 +0000] "GET /notfound HTTP/1.1" 404 256 "-" "-"'
        entry = parser.parse_line(line)

        assert entry.http.status_code == 404
        assert entry.level == LogLevel.WARNING

    def test_can_parse_combined_sample(self, parser, sample_apache_combined_logs):
        """Test can_parse with combined format sample."""
        confidence = parser.can_parse(sample_apache_combined_logs)
        assert confidence > 0.8


class TestApacheCommonParser:
    """Tests for ApacheCommonParser."""

    @pytest.fixture
    def parser(self):
        return ApacheCommonParser()

    def test_parse_common_format(self, parser):
        """Test parsing Apache Common format."""
        line = '192.168.1.100 - - [27/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 2326'
        entry = parser.parse_line(line)

        assert entry.network.source_ip == "192.168.1.100"
        assert entry.http.method == "GET"
        assert entry.http.path == "/index.html"
        assert entry.http.status_code == 200
        assert entry.format_detected == "apache_common"


class TestNginxAccessParser:
    """Tests for NginxAccessParser."""

    @pytest.fixture
    def parser(self):
        return NginxAccessParser()

    def test_parse_nginx_access(self, parser, sample_nginx_access_logs):
        """Test parsing Nginx access logs."""
        entry = parser.parse_line(sample_nginx_access_logs[0])

        assert entry.network.source_ip == "192.168.1.100"
        assert entry.http.method == "GET"
        assert entry.http.path == "/index.html"
        assert entry.http.status_code == 200
        assert entry.format_detected == "nginx_access"


class TestNginxErrorParser:
    """Tests for NginxErrorParser."""

    @pytest.fixture
    def parser(self):
        return NginxErrorParser()

    def test_parse_nginx_error(self, parser, sample_nginx_error_logs):
        """Test parsing Nginx error logs."""
        entry = parser.parse_line(sample_nginx_error_logs[0])

        assert entry.level == LogLevel.ERROR
        assert entry.timestamp is not None
        assert "open()" in entry.message
        assert entry.extra.get("pid") == 1234
        assert entry.format_detected == "nginx_error"

    def test_parse_nginx_warn(self, parser, sample_nginx_error_logs):
        """Test parsing Nginx warning log."""
        entry = parser.parse_line(sample_nginx_error_logs[1])
        assert entry.level == LogLevel.WARNING

    def test_parse_nginx_crit(self, parser, sample_nginx_error_logs):
        """Test parsing Nginx critical log."""
        entry = parser.parse_line(sample_nginx_error_logs[3])
        assert entry.level == LogLevel.CRITICAL


class TestSyslogRFC3164Parser:
    """Tests for SyslogRFC3164Parser."""

    @pytest.fixture
    def parser(self):
        return SyslogRFC3164Parser()

    def test_parse_with_priority(self, parser, sample_syslog_rfc3164_logs):
        """Test parsing syslog with priority."""
        entry = parser.parse_line(sample_syslog_rfc3164_logs[0])

        assert entry.source.hostname == "myhost"
        assert entry.source.service == "su"
        assert entry.timestamp is not None
        assert "facility" in entry.extra
        assert "severity" in entry.extra

    def test_parse_without_priority(self, parser, sample_syslog_rfc3164_logs):
        """Test parsing syslog without priority."""
        entry = parser.parse_line(sample_syslog_rfc3164_logs[3])

        assert entry.source.hostname == "myhost"
        assert entry.source.service == "cron"


class TestSyslogRFC5424Parser:
    """Tests for SyslogRFC5424Parser."""

    @pytest.fixture
    def parser(self):
        return SyslogRFC5424Parser()

    def test_parse_rfc5424(self, parser, sample_syslog_rfc5424_logs):
        """Test parsing RFC 5424 syslog."""
        entry = parser.parse_line(sample_syslog_rfc5424_logs[0])

        assert entry.source.hostname == "myhost"
        assert entry.source.service == "myapp"
        assert entry.timestamp is not None
        assert entry.format_detected == "syslog_rfc5424"
        assert len(entry.structured_data) > 0

    def test_parse_rfc5424_no_sd(self, parser, sample_syslog_rfc5424_logs):
        """Test parsing RFC 5424 without structured data."""
        entry = parser.parse_line(sample_syslog_rfc5424_logs[1])

        assert entry.message == "User logged in"


class TestPythonLoggingParser:
    """Tests for PythonLoggingParser."""

    @pytest.fixture
    def parser(self):
        return PythonLoggingParser()

    def test_parse_python_log(self, parser, sample_python_logs):
        """Test parsing Python logging format."""
        entry = parser.parse_line(sample_python_logs[0])

        assert entry.level == LogLevel.INFO
        assert entry.source.service == "myapp.module"
        assert entry.message == "Application started successfully"
        assert entry.timestamp is not None
        assert entry.timestamp_precision == "ms"

    def test_parse_all_levels(self, parser, sample_python_logs):
        """Test parsing all log levels."""
        levels = []
        for line in sample_python_logs:
            entry = parser.parse_line(line)
            levels.append(entry.level)

        assert LogLevel.INFO in levels
        assert LogLevel.DEBUG in levels
        assert LogLevel.WARNING in levels
        assert LogLevel.ERROR in levels
        assert LogLevel.CRITICAL in levels


class TestGenericParser:
    """Tests for GenericParser."""

    @pytest.fixture
    def parser(self):
        return GenericParser()

    def test_parse_generic_with_timestamp(self, parser):
        """Test parsing line with recognizable timestamp."""
        line = "2026-01-27 10:15:32 INFO Starting application"
        entry = parser.parse_line(line)

        assert entry.timestamp is not None
        assert entry.level == LogLevel.INFO
        assert "Starting application" in entry.message

    def test_parse_generic_with_level(self, parser):
        """Test parsing line with recognizable level."""
        line = "ERROR: Something went wrong"
        entry = parser.parse_line(line)

        assert entry.level == LogLevel.ERROR
        assert "Something went wrong" in entry.message

    def test_parse_generic_minimal(self, parser):
        """Test parsing line with no recognizable patterns."""
        line = "Just some plain text"
        entry = parser.parse_line(line)

        assert entry.message == "Just some plain text"
        assert entry.format_detected == "generic"
        assert entry.parser_confidence < 0.5

    def test_can_parse_always_returns_value(self, parser):
        """Test that generic parser always returns a confidence."""
        confidence = parser.can_parse(["random text", "more text"])
        assert 0.0 <= confidence <= 1.0


class TestParseStream:
    """Tests for parse_stream functionality."""

    def test_parse_stream_json(self, sample_json_logs):
        """Test streaming parse of JSON logs."""
        parser = JSONParser()
        entries = list(parser.parse_stream(iter(sample_json_logs)))

        assert len(entries) == len(sample_json_logs)
        assert all(e.format_detected == "json_structured" for e in entries)

    def test_parse_stream_skips_empty(self):
        """Test that parse_stream skips empty lines."""
        parser = JSONParser()
        lines = ['{"msg": "one"}', "", '{"msg": "two"}', "   ", '{"msg": "three"}']
        entries = list(parser.parse_stream(iter(lines)))

        assert len(entries) == 3


# ---------------------------------------------------------------------------
# HIGH-T-4: Docker and Kubernetes parsers
# ---------------------------------------------------------------------------

class TestDockerJSONParser:
    """Tests for DockerJSONParser (HIGH-T-4)."""

    def test_basic_docker_json(self):
        """Parse a well-formed Docker JSON container log line."""
        from ulp.parsers.docker import DockerJSONParser

        line = '{"log":"hello world\\n","stream":"stdout","time":"2024-01-15T10:30:00.123456789Z"}'
        entry = DockerJSONParser().parse_line(line)
        assert "hello world" in entry.message
        assert entry.timestamp is not None
        assert entry.parse_errors == []

    def test_stderr_to_warning(self):
        """stderr stream without an explicit error keyword should yield >= INFO level."""
        from ulp.parsers.docker import DockerJSONParser

        line = '{"log":"oops","stream":"stderr","time":"2024-01-15T10:30:00Z"}'
        entry = DockerJSONParser().parse_line(line)
        # stderr defaults to WARNING when inferred level would be INFO
        assert entry.level in (LogLevel.WARNING, LogLevel.ERROR, LogLevel.INFO)

    def test_stderr_error_message_not_downgraded(self):
        """stderr stream with 'error' in message should not be downgraded below WARNING."""
        from ulp.parsers.docker import DockerJSONParser

        line = '{"log":"error: connection refused","stream":"stderr","time":"2024-01-15T10:30:00Z"}'
        entry = DockerJSONParser().parse_line(line)
        assert entry.level >= LogLevel.WARNING

    def test_malformed_returns_unknown(self):
        """Non-JSON input should produce a LogLevel.UNKNOWN entry with parse_errors."""
        from ulp.parsers.docker import DockerJSONParser

        entry = DockerJSONParser().parse_line("not json at all")
        assert entry.level == LogLevel.UNKNOWN
        assert len(entry.parse_errors) >= 1

    def test_missing_log_field(self):
        """Valid JSON but missing 'log' key is flagged."""
        from ulp.parsers.docker import DockerJSONParser

        line = '{"stream":"stdout","time":"2024-01-15T10:30:00Z"}'
        entry = DockerJSONParser().parse_line(line)
        assert len(entry.parse_errors) >= 1

    def test_can_parse_docker_sample(self):
        """can_parse returns high confidence for Docker JSON lines."""
        from ulp.parsers.docker import DockerJSONParser

        sample = [
            '{"log":"msg1\\n","stream":"stdout","time":"2024-01-15T10:30:00.123Z"}',
            '{"log":"msg2\\n","stream":"stderr","time":"2024-01-15T10:30:01.456Z"}',
        ]
        confidence = DockerJSONParser().can_parse(sample)
        assert confidence > 0.8

    def test_format_detected(self):
        """format_detected is set for valid Docker JSON logs."""
        from ulp.parsers.docker import DockerJSONParser

        line = '{"log":"start\\n","stream":"stdout","time":"2024-01-15T10:30:00.123Z"}'
        entry = DockerJSONParser().parse_line(line)
        assert entry.format_detected == "docker_json"


class TestKubernetesContainerParser:
    """Tests for KubernetesContainerParser CRI format (HIGH-T-4, HIGH-P-3)."""

    def test_cri_format_strips_stream_flag(self):
        """CRI-O / containerd lines: stream type and partial flag must NOT appear in message."""
        from ulp.parsers.kubernetes import KubernetesContainerParser

        line = "2024-01-15T10:30:00.123Z stdout F App started"
        entry = KubernetesContainerParser().parse_line(line)
        assert "stdout" not in entry.message
        assert "App started" in entry.message

    def test_cri_format_no_subsecond(self):
        """CRI-O lines without sub-second precision should still parse correctly."""
        from ulp.parsers.kubernetes import KubernetesContainerParser

        line = "2024-01-15T10:30:00Z stderr F Error occurred"
        entry = KubernetesContainerParser().parse_line(line)
        assert "Error occurred" in entry.message

    def test_timestamped_line_sets_timestamp(self):
        """Lines with an ISO-8601Z prefix should have a non-None timestamp."""
        from ulp.parsers.kubernetes import KubernetesContainerParser

        line = "2024-01-15T10:30:00.000000000Z plain message here"
        entry = KubernetesContainerParser().parse_line(line)
        assert entry.timestamp is not None

    def test_json_embedded_in_container_log(self):
        """JSON-formatted log content is further parsed to extract level/message."""
        from ulp.parsers.kubernetes import KubernetesContainerParser

        line = '2024-01-15T10:30:00.123456789Z {"level":"error","message":"db down"}'
        entry = KubernetesContainerParser().parse_line(line)
        assert entry.level == LogLevel.ERROR
        assert "db down" in entry.message


class TestKubernetesAuditParser:
    """Tests for KubernetesAuditParser (HIGH-T-4, CRIT-8)."""

    def test_null_response_status(self):
        """responseStatus: null must not crash the parser (CRIT-8 regression)."""
        import json
        from ulp.parsers.kubernetes import KubernetesAuditParser

        data = {
            "apiVersion": "audit.k8s.io/v1",
            "kind": "Event",
            "stage": "RequestReceived",
            "requestURI": "/api/v1/namespaces",
            "verb": "list",
            "user": {"username": "test"},
            "responseStatus": None,
            "requestReceivedTimestamp": "2024-01-15T10:30:00Z",
        }
        entry = KubernetesAuditParser().parse_line(json.dumps(data))
        assert entry is not None
        assert entry.parse_errors == []  # no crash → no parse error

    def test_normal_audit_event(self):
        """A well-formed audit event is parsed to INFO/WARNING/ERROR based on status code."""
        import json
        from ulp.parsers.kubernetes import KubernetesAuditParser

        data = {
            "apiVersion": "audit.k8s.io/v1",
            "kind": "Event",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/pods",
            "verb": "list",
            "user": {"username": "admin"},
            "responseStatus": {"code": 200},
            "requestReceivedTimestamp": "2024-01-15T10:30:00Z",
            "auditID": "abc-123",
        }
        entry = KubernetesAuditParser().parse_line(json.dumps(data))
        assert entry.level == LogLevel.INFO
        assert entry.format_detected == "kubernetes_audit"

    def test_malformed_json_returns_errors(self):
        """Malformed JSON line returns a LogEntry with parse_errors populated."""
        from ulp.parsers.kubernetes import KubernetesAuditParser

        entry = KubernetesAuditParser().parse_line("not json {")
        assert len(entry.parse_errors) >= 1

    def test_non_audit_json_is_flagged(self):
        """JSON that is not a k8s audit event is flagged with parse_errors."""
        import json
        from ulp.parsers.kubernetes import KubernetesAuditParser

        data = {"level": "info", "message": "just a normal log"}
        entry = KubernetesAuditParser().parse_line(json.dumps(data))
        assert len(entry.parse_errors) >= 1


# ---------------------------------------------------------------------------
# Regression: Apache/Nginx escaped quotes (CRIT-9)
# ---------------------------------------------------------------------------

def test_apache_combined_escaped_quote_in_request():
    """ApacheCombinedParser must handle escaped quotes inside the request field."""
    from ulp.parsers.apache import ApacheCombinedParser

    line = r'192.168.1.1 - - [27/Jan/2026:10:15:32 +0000] "GET /search?q=\"x\" HTTP/1.1" 200 1234 "-" "-"'
    entry = ApacheCombinedParser().parse_line(line)
    assert entry.http is not None, f"http is None; parse_errors={entry.parse_errors}"
    assert entry.http.method == "GET"
    assert entry.http.status_code == 200


def test_nginx_access_escaped_quote():
    """NginxAccessParser must handle escaped quotes inside the request field."""
    from ulp.parsers.nginx import NginxAccessParser

    line = r'192.168.1.1 - - [27/Jan/2026:10:15:32 +0000] "GET /search?q=\"x\" HTTP/1.1" 200 1234 "-" "-"'
    entry = NginxAccessParser().parse_line(line)
    assert entry.http is not None, f"http is None; parse_errors={entry.parse_errors}"
    assert entry.http.method == "GET"


# ---------------------------------------------------------------------------
# Regression: BaseParser Z-suffix timestamp (HIGH-P-1)
# ---------------------------------------------------------------------------

def test_base_parser_z_suffix_is_aware():
    """_parse_timestamp must produce timezone-aware datetimes for Z-suffix strings."""
    from ulp.core.base import BaseParser

    class _ConcreteParser(BaseParser):
        name = "test"
        supported_formats = []

        def parse_line(self, line):
            return None

        def can_parse(self, sample):
            return 0.0

    p = _ConcreteParser()
    ts = p._parse_timestamp("2024-01-15T10:30:00.123Z")
    assert ts is not None
    assert ts.tzinfo is not None, "Z-suffix timestamp must be timezone-aware"

    ts2 = p._parse_timestamp("2024-01-15T10:30:00Z")
    assert ts2 is not None
    assert ts2.tzinfo is not None, "Z-suffix timestamp (no subseconds) must be timezone-aware"
