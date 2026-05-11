# Core Models Reference

**Last Updated:** January 29, 2026

This document describes the core data models used throughout ULP.

## Overview

All log formats are normalized into a common `LogEntry` structure with supporting models for different contexts (HTTP, network, correlation). This allows uniform processing regardless of the original log format.

## LogEntry

The universal normalized log entry. All format-specific parsers produce instances of this class.

**Location:** `ulp.core.models.LogEntry`

### Fields

```python
@dataclass
class LogEntry:
    # Core identification
    id: UUID                        # Unique identifier for this entry
    raw: str                        # Original unparsed line

    # Temporal information
    timestamp: datetime | None      # When the event occurred
    timestamp_precision: str        # "ms", "us", "ns", "s", "unknown"

    # Classification
    level: LogLevel                 # Severity level
    format_detected: str            # Format name (e.g., "nginx_access")

    # Content
    message: str                    # Human-readable message
    structured_data: dict[str, Any] # Format-specific structured fields

    # Source metadata
    source: LogSource              # Where this log came from

    # Context (optional, populated when available)
    network: NetworkInfo | None    # Network-related fields
    http: HTTPInfo | None          # HTTP-specific fields
    correlation: CorrelationIds    # IDs for cross-log correlation

    # Parsing metadata
    parser_name: str               # Parser that handled this entry
    parser_confidence: float       # 0.0-1.0 confidence score
    parse_errors: list[str]        # Any errors during parsing

    # Extension point
    extra: dict[str, Any]          # Custom format-specific data
```

### Methods

#### `is_error() -> bool`

Check if this is an error-level or higher entry.

```python
entry = parse("app.log")[0]
if entry.is_error():
    alert_team(entry)
```

#### `formatted_timestamp(fmt: str = "%Y-%m-%d %H:%M:%S") -> str`

Return formatted timestamp string or placeholder.

```python
entry = parse("app.log")[0]
print(entry.formatted_timestamp("%H:%M:%S"))
# Output: "14:23:15"

# Handles missing timestamps
entry_no_ts = LogEntry(message="test")
print(entry_no_ts.formatted_timestamp())
# Output: "-"
```

#### `to_dict() -> dict[str, Any]`

Serialize to dictionary for JSON export.

```python
entry = parse("app.log")[0]
data = entry.to_dict()
json.dump(data, f, indent=2)
```

#### `from_dict(data: dict[str, Any]) -> LogEntry` (classmethod)

Deserialize from dictionary.

```python
with open("entries.json") as f:
    data = json.load(f)
entry = LogEntry.from_dict(data)
```

### Example

```python
from ulp import parse, LogLevel

entries = parse("nginx-access.log")
for entry in entries:
    print(f"ID: {entry.id}")
    print(f"Time: {entry.timestamp}")
    print(f"Level: {entry.level.name}")
    print(f"Message: {entry.message}")

    if entry.http:
        print(f"HTTP: {entry.http.method} {entry.http.path} -> {entry.http.status_code}")

    if entry.network:
        print(f"Client: {entry.network.source_ip}")

    if entry.correlation.request_id:
        print(f"Request ID: {entry.correlation.request_id}")

    print(f"Parsed by: {entry.parser_name} (confidence: {entry.parser_confidence:.0%})")
    print()
```

---

## LogLevel

Enumeration of standard log levels mapped from various formats.

**Location:** `ulp.core.models.LogLevel`

### Values

```python
class LogLevel(Enum):
    TRACE = 0
    DEBUG = 10
    INFO = 20
    NOTICE = 25
    WARNING = 30
    ERROR = 40
    CRITICAL = 50
    ALERT = 60
    EMERGENCY = 70
    UNKNOWN = -1
```

### Methods

#### `from_string(level: str) -> LogLevel` (classmethod)

Parse level string from various formats.

Handles:
- Standard names: "INFO", "info", "warning", "error"
- Abbreviations: "I", "W", "E"
- Syslog numeric: "0"-"7"
- Variants: "warn"→WARNING, "err"→ERROR, "fatal"→CRITICAL

```python
from ulp import LogLevel

level = LogLevel.from_string("ERROR")  # LogLevel.ERROR
level = LogLevel.from_string("E")      # LogLevel.ERROR
level = LogLevel.from_string("err")    # LogLevel.ERROR
level = LogLevel.from_string("3")      # LogLevel.ERROR (syslog)
level = LogLevel.from_string("warn")   # LogLevel.WARNING
level = LogLevel.from_string("unknown") # LogLevel.UNKNOWN
```

### Comparison

LogLevel supports comparison operators:

```python
from ulp import LogLevel

# Filter by severity
entries = parse("app.log")
critical = [e for e in entries if e.level >= LogLevel.ERROR]

# Check specific level
if entry.level == LogLevel.ERROR:
    notify_oncall()

# Range checks
if LogLevel.WARNING <= entry.level < LogLevel.CRITICAL:
    log_to_monitoring(entry)
```

---

## LogSource

Metadata about where a log entry originated.

**Location:** `ulp.core.models.LogSource`

```python
@dataclass
class LogSource:
    file_path: str | None      # Source file path
    line_number: int | None    # Line number in file
    hostname: str | None       # Host that generated the log
    service: str | None        # Service name
    container_id: str | None   # Docker container ID
    pod_name: str | None       # Kubernetes pod name
    namespace: str | None      # Kubernetes namespace
```

### Methods

#### `to_dict() -> dict[str, Any]`

Convert to dictionary, excluding None values.

### Example

```python
entries = parse("app.log")
for entry in entries:
    print(f"File: {entry.source.file_path}")
    print(f"Line: {entry.source.line_number}")
    if entry.source.hostname:
        print(f"Host: {entry.source.hostname}")
    if entry.source.pod_name:
        print(f"Pod: {entry.source.pod_name}")
```

---

## NetworkInfo

Network-related fields extracted from logs (access logs, firewalls, etc.).

**Location:** `ulp.core.models.NetworkInfo`

```python
@dataclass
class NetworkInfo:
    source_ip: str | None          # Client IP address
    destination_ip: str | None     # Server IP address
    source_port: int | None        # Client port
    destination_port: int | None   # Server port
    protocol: str | None           # Network protocol
    user_agent: str | None         # HTTP User-Agent
    referer: str | None            # HTTP Referer
```

### Example

```python
entries = parse("nginx-access.log")
for entry in entries:
    if entry.network:
        print(f"Client: {entry.network.source_ip}")
        print(f"User-Agent: {entry.network.user_agent}")
        if entry.network.referer:
            print(f"Referer: {entry.network.referer}")
```

---

## HTTPInfo

HTTP-specific fields for web server logs.

**Location:** `ulp.core.models.HTTPInfo`

```python
@dataclass
class HTTPInfo:
    method: str | None             # HTTP method (GET, POST, etc.)
    path: str | None               # URL path
    query_string: str | None       # Query parameters
    status_code: int | None        # HTTP status code
    response_size: int | None      # Response body size in bytes
    response_time_ms: float | None # Response time in milliseconds
    http_version: str | None       # HTTP version (HTTP/1.1, etc.)
```

### Example

```python
entries = parse("apache-access.log")

# Find slow requests
slow_requests = [
    e for e in entries
    if e.http and e.http.response_time_ms and e.http.response_time_ms > 1000
]

# Analyze status codes
from collections import Counter
status_codes = Counter(
    e.http.status_code for e in entries if e.http and e.http.status_code
)
print(f"Status code distribution: {status_codes}")

# Find large responses
large = [
    e for e in entries
    if e.http and e.http.response_size and e.http.response_size > 1_000_000
]
```

---

## CorrelationIds

IDs for correlating logs across systems (distributed tracing, sessions).

**Location:** `ulp.core.models.CorrelationIds`

```python
@dataclass
class CorrelationIds:
    request_id: str | None       # Request identifier
    trace_id: str | None         # Distributed trace ID
    span_id: str | None          # Trace span ID
    correlation_id: str | None   # General correlation ID
    session_id: str | None       # User session ID
    user_id: str | None          # User identifier
    transaction_id: str | None   # Transaction ID
```

### Methods

#### `has_any_id() -> bool`

Check if any correlation ID is set.

#### `get_primary_id() -> tuple[str, str] | None`

Get the first non-None correlation ID as (field_name, value).

### Example

```python
entries = parse("app.log")

# Find entries with request IDs
with_ids = [e for e in entries if e.correlation.request_id]

# Group by request
from collections import defaultdict
by_request = defaultdict(list)
for entry in with_ids:
    by_request[entry.correlation.request_id].append(entry)

# Print request flows
for request_id, entries in by_request.items():
    print(f"\nRequest {request_id}:")
    for e in sorted(entries, key=lambda x: x.timestamp or datetime.min):
        print(f"  {e.timestamp}: {e.message}")
```

---

## ParseResult

Result of parsing a log file or stream.

**Location:** `ulp.core.models.ParseResult`

```python
@dataclass
class ParseResult:
    entries: list[LogEntry]     # Parsed log entries
    format_detected: str        # Detected format name
    confidence: float           # Detection confidence (0.0-1.0)
    entry_count: int            # Total entries parsed
    error_count: int            # Entries with parse errors
    source_file: str | None     # Source file path
```

### Methods

#### `filter(level: LogLevel | None = None) -> ParseResult`

Return new ParseResult with filtered entries.

```python
from ulp import parse, LogLevel

# Parse file
result = ParseResult(
    entries=parse("app.log"),
    format_detected="json_structured",
    confidence=0.95,
)

# Filter errors
errors = result.filter(level=LogLevel.ERROR)
print(f"Found {errors.entry_count} errors")
```

#### `to_dict() -> dict[str, Any]`

Serialize to dictionary.

---

## FormatSignature

Defines how to recognize a log format (used by detection engine).

**Location:** `ulp.core.models.FormatSignature`

```python
@dataclass
class FormatSignature:
    name: str                          # Format name
    description: str                   # Human-readable description

    # Detection patterns (in priority order)
    magic_patterns: list[str]          # Regex patterns that uniquely identify format
    line_patterns: list[str]           # Common patterns

    # Structural hints
    is_json: bool                      # Is this a JSON-based format?
    is_multiline: bool                 # Does it span multiple lines?
    typical_line_length: tuple[int, int]  # (min, max) line length

    # Parser binding
    parser_class: str                  # Fully qualified class name

    # Confidence modifiers
    weight: float                      # Higher = more confident when matched (default: 1.0)
```

See [Format Detection](../reference/DETECTION-29JAN2026.md) for usage.

---

## Type Hints and Validation

All models use Python dataclasses with type hints for:

- IDE autocomplete and type checking
- Runtime validation (via mypy, pyright)
- Clear API documentation
- Serialization/deserialization

### Example with Type Checking

```python
from ulp import LogEntry, LogLevel, HTTPInfo

# Type-safe entry creation
entry = LogEntry(
    message="Request processed",
    level=LogLevel.INFO,
    http=HTTPInfo(
        method="GET",
        path="/api/users",
        status_code=200,
    )
)

# IDE will catch this error:
# entry.http.status_code = "200"  # Type error: expected int, got str

# This works:
entry.http.status_code = 200
```

## Immutability Considerations

While the models are dataclasses (technically mutable), they should be treated as immutable after creation. Normalization creates new entries rather than modifying existing ones.

```python
# DON'T: Modify entries in place
entry.message = "modified"

# DO: Create new normalized entry
normalized = normalizer.normalize(entry)
```

## Serialization Example

```python
import json
from ulp import parse

entries = parse("app.log")

# Serialize to JSON
data = {
    "entries": [e.to_dict() for e in entries],
    "count": len(entries),
}

with open("output.json", "w") as f:
    json.dump(data, f, indent=2, default=str)

# Deserialize
with open("output.json") as f:
    data = json.load(f)

from ulp import LogEntry
restored = [LogEntry.from_dict(e) for e in data["entries"]]
```

## Next Steps

- [Public API Reference](PUBLIC-API-29JAN2026.md)
- [Domain Entities](ENTITIES-29JAN2026.md)
- [User Guide](../guides/USER-GUIDE-29JAN2026.md)
