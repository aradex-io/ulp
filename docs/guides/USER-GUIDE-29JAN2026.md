# User Guide

**Last Updated:** January 29, 2026

Comprehensive guide to using Universal Log Parser (ULP) for log analysis and correlation.

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Format Detection](#format-detection)
4. [Parsing Logs](#parsing-logs)
5. [Streaming Large Files](#streaming-large-files)
6. [Log Correlation](#log-correlation)
7. [Filtering and Search](#filtering-and-search)
8. [Output Formats](#output-formats)
9. [Normalization](#normalization)
10. [Python API](#python-api)
11. [Advanced Topics](#advanced-topics)
12. [Best Practices](#best-practices)
13. [Troubleshooting](#troubleshooting)

---

## Installation

### From PyPI

```bash
# Basic installation
pip install ulp

# With optional dependencies
pip install ulp[geoip]      # GeoIP enrichment
pip install ulp[benchmark]  # Benchmarking tools
pip install ulp[all]        # Everything
```

### From Source

```bash
git clone https://github.com/jeremylaratro/ulp.git
cd ulp
pip install -e .
```

### Verify Installation

```bash
ulp --version
# Output: ulp, version 0.2.0

ulp formats
# Shows all supported formats
```

---

## Basic Usage

### CLI Quick Start

```bash
# Parse a log file (auto-detects format)
ulp parse /var/log/nginx/access.log

# Detect format only
ulp detect access.log

# Parse with specific format
ulp parse --format json_structured app.log

# Filter errors
ulp parse --level error app.log

# Output as JSON
ulp parse --output json app.log
```

### Python Quick Start

```python
from ulp import parse, detect_format, LogLevel

# Detect format
format_name, confidence = detect_format("app.log")
print(f"Format: {format_name} ({confidence:.0%})")

# Parse logs
entries = parse("app.log")
print(f"Parsed {len(entries)} entries")

# Filter by level
errors = [e for e in entries if e.level >= LogLevel.ERROR]

# Access fields
for entry in entries[:5]:
    print(f"{entry.timestamp} [{entry.level.name}] {entry.message}")
```

---

## Format Detection

### Automatic Detection

ULP automatically detects log formats by analyzing the first 50 lines:

```bash
ulp detect /var/log/nginx/access.log
# Output: access.log: nginx_access ██████████ 95%
```

**Confidence Levels:**

- **≥80% (Green)**: High confidence - format is correct
- **50-79% (Yellow)**: Medium confidence - likely correct
- **<50% (Red)**: Low confidence - verify manually

### Viewing All Matches

See all potential format matches:

```bash
ulp detect --all app.log

# Output:
# app.log
#   json_structured  ██████████ 95%
#   python_logging   ████░░░░░░ 40%
#   generic          ███░░░░░░░ 30%
```

### Programmatic Detection

```python
from ulp import detect_format

format_name, confidence = detect_format("access.log")

if confidence < 0.5:
    print(f"Warning: Low confidence detection")
    print(f"Consider using --format to force parser")
else:
    print(f"Detected {format_name} with {confidence:.0%} confidence")
```

### Manual Format Selection

If auto-detection fails or you want to force a specific format:

```bash
# Force JSON parser
ulp parse --format json_structured app.log

# Force Nginx parser
ulp parse --format nginx_access access.log
```

See [Parser Reference](../reference/PARSERS-29JAN2026.md) for all format names.

---

## Parsing Logs

### Single File

```bash
ulp parse app.log
```

**Output (table format):**

```
┌──────────────────────┬─────────┬────────────────────────────────┐
│ Timestamp            │ Level   │ Message                        │
├──────────────────────┼─────────┼────────────────────────────────┤
│ 2026-01-29 10:15:32  │ INFO    │ Request processed successfully │
│ 2026-01-29 10:15:33  │ ERROR   │ Database connection failed     │
└──────────────────────┴─────────┴────────────────────────────────┘
```

### Multiple Files

```bash
ulp parse app.log api.log worker.log
```

All files are combined and displayed together.

### From stdin

```bash
# Tail logs and parse
tail -f /var/log/app.log | ulp parse --format json

# Parse compressed files
zcat app.log.gz | ulp parse --format json

# Parse after grep
grep "ERROR" app.log | ulp parse --format python_logging
```

### Python API

```python
from ulp import parse

# Basic parsing
entries = parse("app.log")

# With specific format
entries = parse("app.log", format="json_structured")

# Process entries
for entry in entries:
    if entry.is_error():
        print(f"ERROR at {entry.timestamp}: {entry.message}")

    # Access HTTP fields (if present)
    if entry.http:
        print(f"  HTTP {entry.http.method} {entry.http.path} -> {entry.http.status_code}")

    # Access correlation IDs
    if entry.correlation.request_id:
        print(f"  Request: {entry.correlation.request_id}")
```

---

## Streaming Large Files

For files larger than ~100MB, use streaming mode to avoid loading everything into memory.

### CLI Streaming

```bash
# Stream a large file
ulp stream --format json huge-app.log

# With progress indicator
ulp stream --format docker_json container.log --progress

# JSON output for piping
ulp stream --format json app.log --output json | jq '.level'
```

**Performance:**

- Memory: ~10-20MB regardless of file size
- Speed: 100,000-200,000 lines/second
- Tested with files up to 10GB

### Python Streaming

```python
from ulp import stream_parse, LogLevel

# Stream large file
error_count = 0
for entry in stream_parse("huge.log", format="json"):
    if entry.level >= LogLevel.ERROR:
        error_count += 1
        print(f"{entry.timestamp}: {entry.message}")

print(f"Total errors: {error_count}")
```

### With Progress Tracking

```python
from ulp import stream_parse

def on_progress(bytes_read, total_bytes, lines_read):
    pct = (bytes_read / total_bytes) * 100
    print(f"\rProgress: {pct:.1f}% ({lines_read:,} lines)", end="")

for entry in stream_parse("huge.log", format="json", progress_callback=on_progress):
    # Process entry
    pass

print("\nDone!")
```

### When to Use Streaming

**Use `ulp parse` when:**
- File is <100MB
- Need to sort/filter all entries
- Want to correlate across sources
- Need statistics on entire file

**Use `ulp stream` when:**
- File is >100MB
- Processing line-by-line is sufficient
- Memory is constrained
- Real-time monitoring

---

## Log Correlation

Correlate related log entries across multiple log files.

### By Request ID

Most reliable when logs contain request/trace IDs:

```bash
ulp correlate app.log nginx.log db.log --strategy request_id
```

**Output:**

```
┌────────────────────┬──────────────┬─────────┬──────────────────┬─────────────────────┐
│ Key                │ Type         │ Entries │ Sources          │ Time Range          │
├────────────────────┼──────────────┼─────────┼──────────────────┼─────────────────────┤
│ req-abc123         │ request_id   │ 8       │ app.log, ngin... │ 10:15:32 - 10:15:33 │
│ req-def456         │ request_id   │ 5       │ app.log, db.log  │ 10:15:35 - 10:15:36 │
└────────────────────┴──────────────┴─────────┴──────────────────┴─────────────────────┘

Correlation Results
  Groups found: 47
  Orphan entries: 123
```

### By Timestamp Window

Group logs that happen within a time window:

```bash
# 1-second window (default)
ulp correlate app.log web.log --strategy timestamp

# 500ms window for tighter correlation
ulp correlate --strategy timestamp --window 0.5 service-a.log service-b.log
```

**Use case:** When no explicit IDs exist, but timing indicates relationship.

### By Session

Group by user session:

```bash
ulp correlate app.log auth.log --strategy session
```

Looks for session_id or user_id fields.

### Combined Strategies

Use all strategies together:

```bash
ulp correlate app.log nginx.log db.log --strategy all
```

### Python API

```python
from ulp import correlate

# Basic correlation
result = correlate(["app.log", "nginx.log"], strategy="request_id")

print(f"Found {len(result.groups)} correlation groups")
print(f"Orphan entries: {len(result.orphan_entries)}")
print(f"Correlation rate: {result.statistics['correlation_rate']:.0%}")

# Analyze each group
for group in result.groups:
    print(f"\nRequest {group.correlation_key}:")
    print(f"  Entries: {len(group.entries)}")
    print(f"  Duration: {group.duration_ms()}ms")
    print(f"  Sources: {group.sources}")

    # View chronological timeline
    for entry in group.timeline():
        source_file = entry.source.file_path.split('/')[-1]
        print(f"  [{source_file}] {entry.timestamp}: {entry.message}")
```

### Correlation Strategies Explained

#### 1. Request ID Correlation

Groups entries with matching:
- `request_id`
- `trace_id`
- `correlation_id`
- `transaction_id`
- `span_id`

**Best for:**
- Microservices with distributed tracing
- Systems with explicit request IDs
- Cross-service debugging

**Example:**

```
App log:    [request_id=abc123] Processing order
Web log:    [request_id=abc123] GET /api/order/create
DB log:     [request_id=abc123] INSERT INTO orders
```

All three grouped together by `request_id=abc123`.

#### 2. Timestamp Window Correlation

Groups entries within a time window (default 1 second).

**Best for:**
- Logs without explicit IDs
- Related operations that happen together
- Performance analysis

**Example:**

```
10:15:32.100  Service A: Request received
10:15:32.150  Service B: Processing request
10:15:32.200  Service C: Database query
```

All grouped as they fall within 1-second window.

#### 3. Session Correlation

Groups entries by session_id or user_id across multiple requests.

**Best for:**
- User behavior analysis
- Session debugging
- Multi-request workflows

**Example:**

```
10:15:30  [user_id=user123] Login successful
10:15:35  [user_id=user123] Viewed product page
10:16:00  [user_id=user123] Added to cart
10:16:30  [user_id=user123] Checkout completed
```

All grouped by `user_id=user123` showing user journey.

---

## Filtering and Search

### Filter by Level

```bash
# Show only errors and above
ulp parse --level error app.log

# Show warnings and above
ulp parse --level warning app.log

# Show everything (including debug)
ulp parse --level debug app.log
```

**Python:**

```python
from ulp import parse, LogLevel

entries = parse("app.log")

# Filter errors
errors = [e for e in entries if e.level >= LogLevel.ERROR]

# Filter specific level
warnings = [e for e in entries if e.level == LogLevel.WARNING]

# Range filter
important = [e for e in entries if LogLevel.WARNING <= e.level < LogLevel.CRITICAL]
```

### Search with Regex

```bash
# Search for pattern in message
ulp parse --grep "user.*login" app.log

# Multiple patterns (OR)
ulp parse --grep "(ERROR|WARN|FATAL)" app.log

# Case-sensitive search requires escaping
ulp parse --grep "Error" app.log  # Case-insensitive by default
```

**Python:**

```python
import re
from ulp import parse

entries = parse("app.log")

# Regex search
pattern = re.compile(r"user.*login", re.IGNORECASE)
matches = [e for e in entries if pattern.search(e.message)]

# Simple substring
db_logs = [e for e in entries if "database" in e.message.lower()]
```

### Limit Output

```bash
# Show first 100 entries
ulp parse --limit 100 app.log

# Combine with other filters
ulp parse --level error --limit 50 app.log
```

### Combined Filters

```bash
# Errors matching pattern, limited to 20
ulp parse --level error --grep "database.*timeout" --limit 20 app.log
```

**Python:**

```python
from ulp import parse, LogLevel
import re

entries = parse("app.log")

# Multi-stage filtering
pattern = re.compile(r"database.*timeout")
filtered = [
    e for e in entries
    if e.level >= LogLevel.ERROR
    and pattern.search(e.message)
][:20]
```

---

## Output Formats

### Table (Default)

Pretty table with columns:

```bash
ulp parse app.log --output table
```

Best for: Terminal viewing, human-readable

### JSON

Structured JSON output:

```bash
ulp parse app.log --output json

# Pipe to jq for processing
ulp parse app.log --output json | jq '.[] | select(.level == "ERROR")'

# Save to file
ulp parse app.log --output json > output.json
```

**JSON Structure:**

```json
[
  {
    "id": "uuid-here",
    "timestamp": "2026-01-29T10:15:32Z",
    "level": "ERROR",
    "message": "Database connection failed",
    "source": {
      "file_path": "/logs/app.log",
      "line_number": 42
    },
    "http": {
      "method": "GET",
      "path": "/api/users",
      "status_code": 500
    }
  }
]
```

Best for: Scripting, further processing, data export

### CSV

Comma-separated values:

```bash
ulp parse app.log --output csv

# Import to spreadsheet
ulp parse app.log --output csv > logs.csv
```

Best for: Spreadsheet analysis, data import

### Compact

Single-line format:

```bash
ulp parse app.log --output compact

# Output:
# 10:15:32 INFO  Request processed
# 10:15:33 ERROR Database failed
```

Best for: Grepping, piping, monitoring scripts

---

## Normalization

Normalization transforms logs into a standardized format.

### Enable Normalization

```bash
ulp parse --normalize app.log
```

**Normalization steps:**

1. **Timestamp normalization**: Convert all timestamps to UTC
2. **Level normalization**: Standardize level names
3. **Field mapping**: Map format-specific fields to common schema

### Python API

```python
from ulp import parse, NormalizationPipeline, TimestampNormalizer, LevelNormalizer

# Create custom pipeline
pipeline = NormalizationPipeline([
    TimestampNormalizer(target_tz="UTC"),
    LevelNormalizer(),
])

# Use with application layer
from ulp.application.parse_logs import ParseLogsUseCase
from ulp.infrastructure import FileStreamSource
from ulp.infrastructure.adapters import ParserRegistryAdapter, FormatDetectorAdapter

source = FileStreamSource("app.log")
use_case = ParseLogsUseCase(
    source=source,
    parser_registry=ParserRegistryAdapter(),
    format_detector=FormatDetectorAdapter(),
    normalizer=pipeline,
)

for entry in use_case.execute():
    # All timestamps now in UTC
    print(f"{entry.timestamp} UTC: {entry.message}")
```

### Custom Normalization Steps

```python
from ulp.domain.services import NormalizationStep
from ulp import LogEntry

class IPAnonymizer(NormalizationStep):
    """Anonymize IP addresses in logs."""

    def normalize(self, entry: LogEntry) -> LogEntry:
        if entry.network and entry.network.source_ip:
            # Mask last octet
            ip_parts = entry.network.source_ip.split('.')
            if len(ip_parts) == 4:
                ip_parts[3] = 'xxx'
                entry.network.source_ip = '.'.join(ip_parts)
        return entry

# Use in pipeline
pipeline = NormalizationPipeline([
    IPAnonymizer(),
    TimestampNormalizer(),
])
```

---

## Python API

### High-Level API

Simple functions for common tasks:

```python
from ulp import parse, detect_format, stream_parse, correlate
from ulp import LogLevel, LogEntry

# Detection
format_name, confidence = detect_format("app.log")

# Parsing
entries = parse("app.log")
entries = parse("app.log", format="json")

# Streaming
for entry in stream_parse("huge.log", format="json"):
    process(entry)

# Correlation
result = correlate(["app.log", "web.log"], strategy="request_id")
```

### Working with LogEntry

```python
from ulp import parse

entries = parse("access.log")
entry = entries[0]

# Core fields
print(entry.timestamp)          # datetime object
print(entry.level)              # LogLevel enum
print(entry.message)            # str
print(entry.raw)                # Original log line

# Source information
print(entry.source.file_path)   # Source file
print(entry.source.line_number) # Line number
print(entry.source.hostname)    # Host (if available)

# HTTP fields (if present)
if entry.http:
    print(entry.http.method)          # GET, POST, etc.
    print(entry.http.path)            # /api/users
    print(entry.http.status_code)     # 200, 404, etc.
    print(entry.http.response_size)   # Bytes
    print(entry.http.response_time_ms)# Response time

# Network fields (if present)
if entry.network:
    print(entry.network.source_ip)    # Client IP
    print(entry.network.user_agent)   # User-Agent
    print(entry.network.referer)      # Referer

# Correlation IDs (if present)
print(entry.correlation.request_id)   # Request ID
print(entry.correlation.trace_id)     # Trace ID
print(entry.correlation.session_id)   # Session ID

# Structured data
print(entry.structured_data)    # dict of format-specific fields

# Metadata
print(entry.parser_name)        # Parser used
print(entry.parser_confidence)  # Confidence score
print(entry.parse_errors)       # Any parse errors
```

### Analyzing Logs

```python
from ulp import parse, LogLevel
from collections import Counter
from datetime import timedelta

entries = parse("app.log")

# Count by level
level_counts = Counter(e.level for e in entries)
print(f"Errors: {level_counts[LogLevel.ERROR]}")

# Find slow requests (>1 second)
slow = [
    e for e in entries
    if e.http and e.http.response_time_ms and e.http.response_time_ms > 1000
]
print(f"Slow requests: {len(slow)}")

# Group by hour
from collections import defaultdict
by_hour = defaultdict(list)
for entry in entries:
    if entry.timestamp:
        hour = entry.timestamp.replace(minute=0, second=0, microsecond=0)
        by_hour[hour].append(entry)

for hour, hour_entries in sorted(by_hour.items()):
    error_count = sum(1 for e in hour_entries if e.is_error())
    print(f"{hour}: {len(hour_entries)} entries, {error_count} errors")

# Top IP addresses
if entries[0].network:
    ips = Counter(e.network.source_ip for e in entries if e.network)
    print("Top 10 IPs:")
    for ip, count in ips.most_common(10):
        print(f"  {ip}: {count}")
```

### Serialization

```python
import json
from ulp import parse, LogEntry

# Serialize to JSON
entries = parse("app.log")
data = [e.to_dict() for e in entries]

with open("output.json", "w") as f:
    json.dump(data, f, indent=2, default=str)

# Deserialize
with open("output.json") as f:
    data = json.load(f)

restored_entries = [LogEntry.from_dict(d) for d in data]
```

---

## Advanced Topics

### Custom Parsers

Create parsers for custom log formats:

```python
from ulp.core.base import BaseParser
from ulp import LogEntry, LogLevel
from ulp.parsers import registry
import re

class MyAppParser(BaseParser):
    name = "myapp"
    supported_formats = ["myapp", "myapp_logs"]

    PATTERN = re.compile(
        r'^\[(?P<timestamp>[^\]]+)\] (?P<level>\w+): (?P<message>.*)'
    )

    def parse_line(self, line: str) -> LogEntry:
        match = self.PATTERN.match(line)
        if not match:
            return self._create_error_entry(line, "Pattern mismatch")

        return LogEntry(
            raw=line,
            timestamp=self._parse_timestamp(match.group('timestamp')),
            level=self._parse_level(match.group('level')),
            message=match.group('message'),
            parser_name=self.name,
            parser_confidence=0.95,
        )

    def can_parse(self, sample: list[str]) -> float:
        matches = sum(1 for line in sample if self.PATTERN.match(line))
        return matches / len(sample) if sample else 0.0

# Register
registry.register(MyAppParser)

# Use
from ulp import parse
entries = parse("myapp.log", format="myapp")
```

See [Custom Parsers Guide](../reference/CUSTOM-PARSERS-29JAN2026.md) for full details.

### Batch Processing

Process multiple files in parallel:

```python
from ulp import parse
from multiprocessing import Pool
from pathlib import Path

def process_file(file_path):
    """Process a single file."""
    entries = parse(str(file_path))
    errors = [e for e in entries if e.is_error()]
    return file_path.name, len(entries), len(errors)

# Find all log files
log_files = list(Path("/var/log").glob("*.log"))

# Process in parallel
with Pool(4) as pool:
    results = pool.map(process_file, log_files)

# Print summary
for filename, total, errors in results:
    error_rate = (errors / total * 100) if total > 0 else 0
    print(f"{filename}: {total} entries, {errors} errors ({error_rate:.1f}%)")
```

### Integration with Monitoring Systems

Send parsed logs to monitoring:

```python
from ulp import stream_parse, LogLevel
import requests

WEBHOOK_URL = "https://monitoring.example.com/webhook"

for entry in stream_parse("app.log", format="json"):
    if entry.level >= LogLevel.ERROR:
        # Send to monitoring system
        payload = {
            "timestamp": entry.timestamp.isoformat(),
            "level": entry.level.name,
            "message": entry.message,
            "source": entry.source.hostname or "unknown",
        }
        requests.post(WEBHOOK_URL, json=payload)
```

---

## Best Practices

### 1. Use Streaming for Large Files

**Don't:**

```python
# Loads entire 5GB file into memory
entries = parse("huge-5gb.log")
```

**Do:**

```python
# Constant memory usage
for entry in stream_parse("huge-5gb.log", format="json"):
    process(entry)
```

### 2. Detect Format Before Batch Processing

**Don't:**

```bash
# Wastes time auto-detecting for each file
for file in *.log; do ulp parse "$file"; done
```

**Do:**

```bash
# Detect once, then use explicit format
FORMAT=$(ulp detect app.log | awk '{print $2}')
for file in *.log; do ulp parse --format "$FORMAT" "$file"; done
```

### 3. Use JSON Output for Scripting

**Don't:**

```bash
# Parsing table output is fragile
ulp parse app.log | grep ERROR | awk '{print $3}'
```

**Do:**

```bash
# Use JSON with jq
ulp parse app.log --output json | jq -r '.[] | select(.level == "ERROR") | .message'
```

### 4. Filter Early

**Don't:**

```python
# Parse everything, then filter
entries = parse("huge.log")
errors = [e for e in entries if e.is_error()]
```

**Do:**

```bash
# Filter during parsing (CLI)
ulp parse --level error huge.log

# Or stream with early filtering (Python)
errors = (e for e in stream_parse("huge.log", format="json") if e.is_error())
```

### 5. Specify Format for Production

**Don't:**

```python
# Auto-detection adds overhead
entries = parse("app.log")
```

**Do:**

```python
# Explicit format is faster
entries = parse("app.log", format="json_structured")
```

### 6. Use Correlation for Debugging

When debugging distributed systems:

```python
from ulp import correlate

result = correlate(
    ["gateway.log", "auth.log", "api.log", "database.log"],
    strategy="request_id"
)

# Find failed requests
for group in result.groups:
    if any(e.is_error() for e in group.entries):
        print(f"\nFailed request {group.correlation_key}:")
        for entry in group.timeline():
            svc = entry.source.service or "unknown"
            print(f"  [{svc}] {entry.timestamp}: {entry.message}")
```

---

## Troubleshooting

### Issue: Low Detection Confidence

**Symptom:**

```
Warning: Low confidence detection (35%)
```

**Solutions:**

1. Check if format is actually supported:
   ```bash
   ulp formats
   ```

2. Try forcing generic parser:
   ```bash
   ulp parse --format generic app.log
   ```

3. Verify log format with sample lines:
   ```bash
   head -n 5 app.log
   ```

4. Create custom parser for your format

### Issue: Memory Error

**Symptom:**

```
MemoryError: Unable to allocate array
```

**Solutions:**

1. Use streaming instead:
   ```bash
   ulp stream --format json huge.log
   ```

2. Process in chunks:
   ```bash
   split -l 100000 huge.log chunk_
   for file in chunk_*; do ulp parse "$file"; done
   ```

### Issue: Slow Performance

**Symptoms:**

- Parsing takes very long
- High CPU usage

**Solutions:**

1. Use explicit format (skip detection):
   ```bash
   ulp parse --format json app.log  # Faster
   ```

2. Filter earlier:
   ```bash
   grep ERROR app.log | ulp parse --format python_logging
   ```

3. Use streaming for large files:
   ```bash
   ulp stream --format json huge.log
   ```

### Issue: Parse Errors

**Symptom:**

```python
entry.parse_errors = ["Line does not match format"]
```

**Solutions:**

1. Check format detection:
   ```python
   format_name, confidence = detect_format("app.log")
   if confidence < 0.5:
       print("Low confidence, try different format")
   ```

2. Try generic parser:
   ```python
   entries = parse("app.log", format="generic")
   ```

3. Examine problematic lines:
   ```python
   errors = [e for e in entries if e.parse_errors]
   for e in errors[:5]:
       print(f"Line {e.source.line_number}: {e.raw}")
       print(f"Errors: {e.parse_errors}")
   ```

### Issue: Missing Correlation IDs

**Symptom:**

```
Correlation found 0 groups
```

**Solutions:**

1. Verify logs contain IDs:
   ```python
   entries = parse("app.log")
   with_ids = [e for e in entries if e.correlation.request_id]
   print(f"{len(with_ids)}/{len(entries)} have request IDs")
   ```

2. Try timestamp correlation:
   ```bash
   ulp correlate --strategy timestamp app.log web.log
   ```

3. Check structured_data for IDs:
   ```python
   for entry in entries[:5]:
       print(entry.structured_data.keys())
   ```

---

## Next Steps

- [CLI Reference](CLI-REFERENCE-29JAN2026.md) - Complete CLI documentation
- [Public API](../api/PUBLIC-API-29JAN2026.md) - Python API reference
- [Parser Reference](../reference/PARSERS-29JAN2026.md) - Supported formats
- [Architecture](../ARCHITECTURE-29JAN2026.md) - System design
- [Examples](../examples/COMMON-EXAMPLES-29JAN2026.md) - Practical examples
