# Supported Log Formats

**Last Updated:** January 29, 2026

Complete reference for all log formats supported by ULP, with examples and field mappings.

## Overview

ULP supports 10+ log formats out of the box, with automatic detection. Each parser extracts format-specific fields into the normalized `LogEntry` structure.

## Quick Reference

| Format | Parser Name | Use Case | Auto-Detect |
|--------|-------------|----------|-------------|
| JSON/JSONL | `json_structured` | Structured application logs | ✅ High |
| Apache Combined | `apache_combined` | Apache web server access logs | ✅ High |
| Apache Common | `apache_common` | Apache CLF logs | ✅ High |
| Nginx Access | `nginx_access` | Nginx web server access logs | ✅ High |
| Nginx Error | `nginx_error` | Nginx error logs | ✅ High |
| Syslog RFC 3164 | `syslog_rfc3164` | BSD syslog format | ✅ Medium |
| Syslog RFC 5424 | `syslog_rfc5424` | Modern syslog format | ✅ High |
| Python Logging | `python_logging` | Python logging module output | ✅ Medium |
| Docker JSON | `docker_json` | Docker JSON log driver | ✅ High |
| Docker Daemon | `docker_daemon` | Docker daemon logs | ✅ Medium |
| Kubernetes Container | `kubernetes_container` | K8s container logs | ✅ High |
| Kubernetes Component | `kubernetes_component` | K8s system component logs | ✅ Medium |
| Kubernetes Audit | `kubernetes_audit` | K8s audit logs | ✅ High |
| Kubernetes Event | `kubernetes_event` | K8s event logs | ✅ Medium |
| Generic | `generic` | Fallback for unknown formats | ✅ Low |

---

## Detailed Format Reference

### JSON Structured Logs

**Parser Name:** `json_structured`, `json`, `jsonl`

**Description:** Structured JSON logs, one JSON object per line (JSONL format).

**Example:**

```json
{"timestamp":"2026-01-29T10:15:32.123Z","level":"INFO","message":"Request processed","request_id":"req-abc123","http":{"method":"GET","path":"/api/users","status_code":200},"response_time_ms":45.2}
```

**Field Mapping:**

| JSON Field | LogEntry Field | Notes |
|------------|----------------|-------|
| `timestamp`, `time`, `@timestamp` | `timestamp` | Parsed as ISO8601 |
| `level`, `severity`, `log_level` | `level` | Normalized to LogLevel enum |
| `message`, `msg`, `text` | `message` | Main log message |
| `request_id`, `trace_id`, `correlation_id` | `correlation.request_id` | Correlation IDs |
| `http.method` | `http.method` | HTTP method |
| `http.status_code`, `status` | `http.status_code` | HTTP status |
| `http.path`, `url` | `http.path` | URL path |
| `source_ip`, `client_ip`, `ip` | `network.source_ip` | Client IP |
| `user_agent` | `network.user_agent` | User-Agent header |
| All other fields | `structured_data` | Preserved as-is |

**Detection Confidence:** 100% if valid JSON

**CLI Usage:**

```bash
ulp parse app.log --format json_structured
ulp stream --format json huge-app.log
```

**Python Usage:**

```python
from ulp import parse

entries = parse("app.log", format="json_structured")
for entry in entries:
    print(entry.correlation.request_id)
    print(entry.structured_data)  # All JSON fields
```

---

### Apache Combined Log Format

**Parser Name:** `apache_combined`, `combined`

**Description:** Apache Combined Log Format (CLF with referer and user-agent).

**Format:**

```
%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
```

**Example:**

```
192.168.1.100 - frank [29/Jan/2026:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 2326 "https://example.com/home" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**Field Mapping:**

| CLF Field | LogEntry Field | Notes |
|-----------|----------------|-------|
| Remote IP | `network.source_ip` | Client IP address |
| Identity | - | Usually `-` (not stored) |
| Username | `correlation.user_id` | If authenticated |
| Timestamp | `timestamp` | Format: `DD/Mon/YYYY:HH:MM:SS TZ` |
| Request | `http.method`, `http.path`, `http.http_version` | Parsed from request line |
| Status | `http.status_code` | HTTP status code |
| Size | `http.response_size` | Response size in bytes |
| Referer | `network.referer` | HTTP Referer header |
| User-Agent | `network.user_agent` | User-Agent string |

**Level Inference:**

- Status 5xx → ERROR
- Status 4xx → WARNING
- Status 2xx/3xx → INFO

**CLI Usage:**

```bash
ulp parse /var/log/apache2/access.log --format apache_combined
```

---

### Apache Common Log Format

**Parser Name:** `apache_common`, `common`, `clf`

**Description:** Apache Common Log Format (CLF) without referer and user-agent.

**Format:**

```
%h %l %u %t \"%r\" %>s %b
```

**Example:**

```
192.168.1.100 - frank [29/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 2326
```

**Field Mapping:** Same as Combined format, but without `referer` and `user_agent`.

---

### Nginx Access Log

**Parser Name:** `nginx_access`, `nginx_default`, `nginx`

**Description:** Nginx default access log format (similar to Apache Combined).

**Format:**

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

**Example:**

```
192.168.1.100 - - [29/Jan/2026:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 612 "-" "curl/7.68.0"
```

**Field Mapping:** Same as Apache Combined format.

**Custom Formats:** If using custom `log_format`, use `generic` parser or create custom parser.

---

### Nginx Error Log

**Parser Name:** `nginx_error`

**Description:** Nginx error log format.

**Format:**

```
YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message
```

**Example:**

```
2026/01/29 10:15:32 [error] 1234#5678: *9 open() "/var/www/missing.html" failed (2: No such file or directory), client: 192.168.1.100, server: example.com, request: "GET /missing.html HTTP/1.1"
```

**Field Mapping:**

| Nginx Field | LogEntry Field | Notes |
|-------------|----------------|-------|
| Timestamp | `timestamp` | Format: `YYYY/MM/DD HH:MM:SS` |
| Level | `level` | emerg, alert, crit, error, warn, notice, info, debug |
| PID | `extra.pid` | Process ID |
| TID | `extra.tid` | Thread ID |
| CID | `extra.connection_id` | Connection ID (if present) |
| Message | `message` | Error message |

**Level Mapping:**

```python
{
    "emerg": EMERGENCY,
    "alert": ALERT,
    "crit": CRITICAL,
    "error": ERROR,
    "warn": WARNING,
    "notice": NOTICE,
    "info": INFO,
    "debug": DEBUG,
}
```

---

### Syslog RFC 3164 (BSD Syslog)

**Parser Name:** `syslog_rfc3164`, `syslog`, `bsd_syslog`

**Description:** Traditional BSD syslog format.

**Format:**

```
<priority>timestamp hostname tag[pid]: message
```

**Example:**

```
<34>Jan 29 10:15:32 webserver sshd[1234]: Accepted password for admin from 192.168.1.100
```

**Field Mapping:**

| Syslog Field | LogEntry Field | Notes |
|--------------|----------------|-------|
| Priority | `level` | Converted from syslog priority |
| Timestamp | `timestamp` | `MMM DD HH:MM:SS` |
| Hostname | `source.hostname` | Source host |
| Tag | `source.service` | Process name |
| PID | `extra.pid` | Process ID (if present) |
| Message | `message` | Log message |

**Priority to Level:**

```
Priority = Facility * 8 + Severity
Severity: 0=EMERG, 1=ALERT, 2=CRIT, 3=ERROR, 4=WARN, 5=NOTICE, 6=INFO, 7=DEBUG
```

---

### Syslog RFC 5424 (Modern Syslog)

**Parser Name:** `syslog_rfc5424`, `modern_syslog`

**Description:** Modern structured syslog format.

**Format:**

```
<priority>version timestamp hostname app-name procid msgid [structured-data] message
```

**Example:**

```
<34>1 2026-01-29T10:15:32.123Z webserver sshd 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] Accepted password for admin
```

**Field Mapping:**

| Syslog Field | LogEntry Field | Notes |
|--------------|----------------|-------|
| Priority | `level` | Converted from priority |
| Version | - | Syslog version (usually 1) |
| Timestamp | `timestamp` | ISO8601 format |
| Hostname | `source.hostname` | Source host |
| App-name | `source.service` | Application name |
| Procid | `extra.pid` | Process ID |
| Msgid | `extra.msgid` | Message ID |
| Structured-data | `structured_data` | Parsed SD elements |
| Message | `message` | Log message |

---

### Python Logging

**Parser Name:** `python_logging`, `python`

**Description:** Python standard logging module output.

**Format (default):**

```
%(levelname)s:%(name)s:%(message)s
```

**Example:**

```
INFO:myapp.module:User login successful for user_id=123
ERROR:myapp.database:Connection timeout after 30s
2026-01-29 10:15:32,123 - myapp - INFO - Request processed in 45ms
```

**Field Mapping:**

| Python Field | LogEntry Field | Notes |
|--------------|----------------|-------|
| levelname | `level` | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| name | `source.service` | Logger name |
| message | `message` | Log message |
| asctime | `timestamp` | If included in format |

**Supports Multiple Formats:**

- `levelname:name:message`
- `asctime - name - levelname - message`
- Custom formats are parsed best-effort

---

### Docker JSON Logs

**Parser Name:** `docker_json`, `docker`

**Description:** Docker JSON log driver output.

**Format:**

```json
{"log":"2026-01-29 10:15:32 INFO Request processed\n","stream":"stdout","time":"2026-01-29T10:15:32.123456789Z"}
```

**Field Mapping:**

| Docker Field | LogEntry Field | Notes |
|--------------|----------------|-------|
| `log` | `message` (parsed) | Log line (may contain nested format) |
| `stream` | `extra.stream` | stdout or stderr |
| `time` | `timestamp` | Container timestamp |

**Nested Parsing:**

The `log` field is parsed to extract embedded format:

```json
{"log":"[ERROR] Database connection failed\n","stream":"stderr","time":"..."}
```

Results in:
- `level` = ERROR
- `message` = "Database connection failed"

---

### Kubernetes Container Logs

**Parser Name:** `kubernetes_container`, `k8s_container`

**Description:** Kubernetes container logs (combines Docker JSON with K8s metadata).

**Example:**

```
2026-01-29T10:15:32.123456789Z stdout F 2026-01-29 10:15:32 INFO [app] Request processed
```

**Field Mapping:**

| K8s Field | LogEntry Field | Notes |
|-----------|----------------|-------|
| Timestamp | `timestamp` | ISO8601 timestamp |
| Stream | `extra.stream` | stdout/stderr |
| Partial | `extra.partial` | F=full, P=partial |
| Log | `message` (parsed) | Parsed for embedded format |

**Metadata Enrichment:**

If log file path contains K8s metadata:

```
/var/log/pods/namespace_pod-name_uid/container-name/0.log
```

Extracts:
- `source.namespace` = namespace
- `source.pod_name` = pod-name
- `source.container_id` = container-name

---

### Generic Parser

**Parser Name:** `generic`, `unknown`

**Description:** Fallback parser for unknown formats. Best-effort parsing.

**Strategy:**

1. Try to extract timestamp (beginning of line)
2. Try to extract level keywords
3. Use entire line as message
4. Minimal structured data

**Example:**

```
[2026-01-29 10:15:32] Something happened
ERROR: Operation failed
Just a plain log line
```

**Field Mapping:**

- Timestamps extracted if recognizable
- Levels extracted from keywords (ERROR, WARN, INFO, DEBUG)
- Everything else → `message`

**When to Use:**

- Unknown log formats
- Custom application logs
- Ad-hoc log analysis

---

## Format Detection

### Detection Algorithm

1. **JSON Check**: Try parsing as JSON
2. **Pattern Matching**: Match against known regex patterns
3. **Parser Confidence**: Ask each parser to score the sample
4. **Best Match**: Select parser with highest confidence
5. **Threshold**: Use generic if confidence < 0.3

### Sample Size

- Default: 50 lines
- Configurable in `FormatDetector(sample_size=N)`

### Confidence Scores

- 0.9-1.0: High confidence (use this parser)
- 0.5-0.9: Medium confidence (likely correct)
- 0.3-0.5: Low confidence (might work)
- <0.3: Very low (use generic fallback)

### Detection Example

```python
from ulp import detect_format

format_name, confidence = detect_format("access.log")

if confidence > 0.8:
    print(f"High confidence: {format_name}")
elif confidence > 0.5:
    print(f"Medium confidence: {format_name}, verify manually")
else:
    print(f"Low confidence: {format_name}, consider generic parser")
```

---

## Parser Registry

### Listing Formats

```python
from ulp.parsers import registry

# List all parsers
parsers = registry.list_parsers()
# ['json', 'nginx_access', 'apache_combined', ...]

# List all format names
formats = registry.list_formats()
# ['json', 'jsonl', 'json_structured', 'nginx', 'nginx_access', ...]
```

### Getting Parsers

```python
# Get by format name
parser = registry.get_parser("nginx_access")

# Get by parser name
parser = registry.get_parser("nginx")

# Find best parser for sample
sample = ["192.168.1.1 - - [29/Jan/2026:10:15:32 +0000] ..."]
parser, confidence = registry.get_best_parser(sample)
```

---

## Custom Log Formats

### Nginx Custom Format

If using custom Nginx `log_format`:

```nginx
log_format custom '$remote_addr - $request_time - "$request" $status';
```

You'll need to create a custom parser:

```python
from ulp.core.base import BaseParser
from ulp import LogEntry, HTTPInfo, NetworkInfo
import re

class CustomNginxParser(BaseParser):
    name = "nginx_custom"
    supported_formats = ["nginx_custom"]

    PATTERN = re.compile(
        r'^(?P<ip>\S+) - (?P<req_time>[\d.]+) - "(?P<request>[^"]*)" (?P<status>\d+)'
    )

    def parse_line(self, line: str) -> LogEntry:
        match = self.PATTERN.match(line)
        if not match:
            return self._create_error_entry(line, "No match")

        d = match.groupdict()
        return LogEntry(
            raw=line,
            message=f"{d['request']} -> {d['status']}",
            http=HTTPInfo(
                status_code=int(d['status']),
                response_time_ms=float(d['req_time']) * 1000
            ),
            network=NetworkInfo(source_ip=d['ip']),
        )

    def can_parse(self, sample: list[str]) -> float:
        matches = sum(1 for line in sample if self.PATTERN.match(line))
        return matches / len(sample)

# Register and use
from ulp.parsers import registry
registry.register(CustomNginxParser)

from ulp import parse
entries = parse("access.log", format="nginx_custom")
```

See [Custom Parsers Guide](CUSTOM-PARSERS-29JAN2026.md) for details.

---

## Format Examples

### Complete Examples

#### JSON Structured Log

**Input:**

```json
{"timestamp":"2026-01-29T10:15:32.123Z","level":"ERROR","message":"Database connection failed","request_id":"req-abc123","db_host":"db.example.com","retry_count":3}
```

**Parsed LogEntry:**

```python
LogEntry(
    timestamp=datetime(2026, 1, 29, 10, 15, 32, 123000),
    level=LogLevel.ERROR,
    message="Database connection failed",
    correlation=CorrelationIds(request_id="req-abc123"),
    structured_data={
        "db_host": "db.example.com",
        "retry_count": 3
    },
    format_detected="json_structured",
    parser_confidence=1.0,
)
```

#### Nginx Access Log

**Input:**

```
192.168.1.100 - - [29/Jan/2026:10:15:32 +0000] "GET /api/users?page=1 HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
```

**Parsed LogEntry:**

```python
LogEntry(
    timestamp=datetime(2026, 1, 29, 10, 15, 32, tzinfo=timezone.utc),
    level=LogLevel.INFO,
    message="GET /api/users -> 200",
    http=HTTPInfo(
        method="GET",
        path="/api/users",
        query_string="page=1",
        http_version="HTTP/1.1",
        status_code=200,
        response_size=1234,
    ),
    network=NetworkInfo(
        source_ip="192.168.1.100",
        referer="https://example.com",
        user_agent="Mozilla/5.0",
    ),
    format_detected="nginx_access",
    parser_confidence=0.95,
)
```

---

## Next Steps

- [Format Detection](DETECTION-29JAN2026.md)
- [Creating Custom Parsers](CUSTOM-PARSERS-29JAN2026.md)
- [User Guide](../guides/USER-GUIDE-29JAN2026.md)
