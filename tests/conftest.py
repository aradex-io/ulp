"""
Pytest fixtures for ULP tests.
"""

import pytest
from datetime import datetime
from ulp.core.models import LogEntry, LogLevel, LogSource, HTTPInfo, NetworkInfo


# Sample log lines for each format

@pytest.fixture
def sample_json_logs() -> list[str]:
    """Sample JSON structured log lines."""
    return [
        '{"timestamp": "2026-01-27T10:15:32.123Z", "level": "INFO", "message": "Application started", "service": "myapp"}',
        '{"timestamp": "2026-01-27T10:15:33.456Z", "level": "DEBUG", "message": "Processing request", "request_id": "abc-123"}',
        '{"timestamp": "2026-01-27T10:15:34.789Z", "level": "ERROR", "message": "Database connection failed", "error": "timeout"}',
        '{"timestamp": "2026-01-27T10:15:35.000Z", "level": "WARNING", "message": "Cache miss for key user:42"}',
        '{"timestamp": "2026-01-27T10:15:36.111Z", "level": "INFO", "message": "Request completed", "request_id": "abc-123", "duration_ms": 150}',
    ]


@pytest.fixture
def sample_apache_combined_logs() -> list[str]:
    """Sample Apache Combined Log Format lines."""
    return [
        '192.168.1.100 - - [27/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"',
        '192.168.1.101 - admin [27/Jan/2026:10:15:33 +0000] "POST /api/users HTTP/1.1" 201 156 "-" "curl/7.68.0"',
        '192.168.1.102 - - [27/Jan/2026:10:15:34 +0000] "GET /missing.html HTTP/1.1" 404 512 "http://example.com/links" "Mozilla/5.0"',
        '192.168.1.103 - - [27/Jan/2026:10:15:35 +0000] "GET /api/data HTTP/1.1" 500 128 "-" "python-requests/2.28.0"',
        '10.0.0.1 - - [27/Jan/2026:10:15:36 +0000] "GET /favicon.ico HTTP/1.1" 304 0 "-" "Mozilla/5.0"',
    ]


@pytest.fixture
def sample_apache_common_logs() -> list[str]:
    """Sample Apache Common Log Format lines."""
    return [
        '192.168.1.100 - - [27/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 2326',
        '192.168.1.101 - admin [27/Jan/2026:10:15:33 +0000] "POST /api/users HTTP/1.1" 201 156',
        '192.168.1.102 - - [27/Jan/2026:10:15:34 +0000] "GET /missing.html HTTP/1.1" 404 512',
    ]


@pytest.fixture
def sample_nginx_access_logs() -> list[str]:
    """Sample Nginx access log lines."""
    return [
        '192.168.1.100 - - [27/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"',
        '192.168.1.101 - user1 [27/Jan/2026:10:15:33 +0000] "POST /api/login HTTP/1.1" 200 64 "http://app.local/" "Mozilla/5.0"',
        '10.0.0.1 - - [27/Jan/2026:10:15:34 +0000] "GET /health HTTP/1.1" 200 2 "-" "kube-probe/1.25"',
    ]


@pytest.fixture
def sample_nginx_error_logs() -> list[str]:
    """Sample Nginx error log lines."""
    return [
        '2026/01/27 10:15:32 [error] 1234#5678: *9 open() "/var/www/html/missing.html" failed (2: No such file or directory)',
        '2026/01/27 10:15:33 [warn] 1234#5678: *10 upstream server temporarily disabled',
        '2026/01/27 10:15:34 [info] 1234#5678: *11 client closed connection while waiting for request',
        '2026/01/27 10:15:35 [crit] 1234#5678: *12 SSL_read() failed (SSL: error:0A000126)',
    ]


@pytest.fixture
def sample_syslog_rfc3164_logs() -> list[str]:
    """Sample RFC 3164 syslog lines."""
    return [
        '<34>Jan 27 10:15:32 myhost su[1234]: pam_unix(su:session): session opened for user root',
        '<38>Jan 27 10:15:33 myhost sshd[5678]: Accepted publickey for user1 from 192.168.1.100 port 54321',
        '<27>Jan 27 10:15:34 myhost kernel: [12345.678] Out of memory: Killed process 9999 (java)',
        'Jan 27 10:15:35 myhost cron[2468]: (root) CMD (/usr/local/bin/backup.sh)',
    ]


@pytest.fixture
def sample_syslog_rfc5424_logs() -> list[str]:
    """Sample RFC 5424 syslog lines."""
    return [
        '<165>1 2026-01-27T10:15:32.123456Z myhost myapp 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Application started',
        '<134>1 2026-01-27T10:15:33.000Z myhost myapp 1234 ID48 - User logged in',
        '<131>1 2026-01-27T10:15:34.789Z myhost myapp 1234 ID49 [meta seq="1"] Database error: connection refused',
    ]


@pytest.fixture
def sample_python_logs() -> list[str]:
    """Sample Python logging format lines."""
    return [
        '2026-01-27 10:15:32,123 - myapp.module - INFO - Application started successfully',
        '2026-01-27 10:15:33,456 - myapp.db - DEBUG - Executing query: SELECT * FROM users',
        '2026-01-27 10:15:34,789 - myapp.api - WARNING - Rate limit approaching for client 192.168.1.100',
        '2026-01-27 10:15:35,012 - myapp.auth - ERROR - Authentication failed for user admin',
        '2026-01-27 10:15:36,345 - myapp.core - CRITICAL - System shutdown initiated',
    ]


@pytest.fixture
def sample_generic_logs() -> list[str]:
    """Sample generic/unrecognized log lines."""
    return [
        '2026-01-27 10:15:32 INFO Starting application',
        'ERROR: Something went wrong!',
        '[2026/01/27 10:15:34] WARN - Deprecated API called',
        'Application initialized at 10:15:35',
    ]


@pytest.fixture
def sample_log_entry() -> LogEntry:
    """Sample LogEntry for testing."""
    return LogEntry(
        timestamp=datetime(2026, 1, 27, 10, 15, 32),
        level=LogLevel.INFO,
        message="Test log message",
        format_detected="test",
        parser_name="test_parser",
        parser_confidence=0.95,
        source=LogSource(
            file_path="/var/log/test.log",
            line_number=42,
            hostname="testhost",
            service="testservice",
        ),
    )


@pytest.fixture
def sample_http_log_entry() -> LogEntry:
    """Sample LogEntry with HTTP info."""
    return LogEntry(
        timestamp=datetime(2026, 1, 27, 10, 15, 32),
        level=LogLevel.INFO,
        message="GET /api/users -> 200",
        format_detected="apache_combined",
        parser_name="apache_combined",
        parser_confidence=0.98,
        http=HTTPInfo(
            method="GET",
            path="/api/users",
            status_code=200,
            response_size=1024,
            http_version="HTTP/1.1",
        ),
        network=NetworkInfo(
            source_ip="192.168.1.100",
            user_agent="Mozilla/5.0",
        ),
    )


@pytest.fixture
def temp_log_file(tmp_path, sample_apache_combined_logs):
    """Create a temporary log file with sample content."""
    log_file = tmp_path / "test.log"
    log_file.write_text("\n".join(sample_apache_combined_logs))
    return log_file
