# Universal Log Parser (ULP)

[![PyPI version](https://badge.fury.io/py/ulp.svg)](https://badge.fury.io/py/ulp)
[![Python](https://img.shields.io/pypi/pyversions/ulp.svg)](https://pypi.org/project/ulp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/jeremylaratro/ulp/actions/workflows/ci.yml/badge.svg)](https://github.com/jeremylaratro/ulp/actions/workflows/ci.yml)

A Python library and CLI tool to automatically detect, parse, and normalize logs from any format. Built for production workloads with streaming support for large files (1-10GB+) and cross-source log correlation.

## Features

- **Auto-Detection**: Automatically identifies 10+ log formats without configuration
- **Streaming Support**: Memory-efficient parsing for files up to 10GB+ using memory-mapped I/O
- **Log Correlation**: Correlate entries across multiple log sources by request ID, timestamp, or session
- **Normalized Output**: All logs converted to a common schema with structured data extraction
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **Rich CLI**: Beautiful terminal output with multiple formats (table, JSON, CSV, compact)
- **Extensible**: Easy to add custom parsers and normalization steps

## Installation

```bash
pip install ulp
```

With optional dependencies:

```bash
# For GeoIP enrichment
pip install ulp[geoip]

# For benchmarking
pip install ulp[benchmark]

# Everything
pip install ulp[all]
```

## Quick Start

### CLI Usage

```bash
# Parse a log file (format auto-detected)
ulp parse /var/log/nginx/access.log

# Detect format only
ulp detect /var/log/syslog

# Parse with specific format
ulp parse --format json_structured app.log

# Filter by level and output as JSON
ulp parse --level error --output json app.log

# Grep for patterns
ulp parse --grep "user.*login" auth.log

# Limit output
ulp parse --limit 100 app.log

# Stream large files (memory-efficient)
ulp stream --format json huge-file.log

# Correlate logs across multiple files
ulp correlate app.log nginx.log --strategy request_id
```

### Library Usage

```python
from ulp import parse, detect_format, LogLevel

# Detect format
format_name, confidence = detect_format("access.log")
print(f"Format: {format_name} ({confidence:.0%})")

# Parse logs
entries = parse("access.log")

# Filter errors
errors = [e for e in entries if e.level >= LogLevel.ERROR]

# Access normalized fields
for entry in entries:
    print(f"{entry.timestamp} [{entry.level.name}] {entry.message}")
```

### Streaming Large Files

For files that don't fit in memory:

```python
from ulp import stream_parse, LogLevel

# Stream-parse a 5GB log file
for entry in stream_parse("huge.log", format="json"):
    if entry.level >= LogLevel.ERROR:
        print(f"{entry.timestamp}: {entry.message}")
```

### Log Correlation

Correlate related log entries across multiple sources:

```python
from ulp import correlate

# Correlate by request ID across app and web server logs
result = correlate(
    ["app.log", "nginx.log"],
    strategy="request_id"
)

for group in result.groups:
    print(f"Request {group.correlation_key}: {len(group.entries)} entries")
    for entry in group.timeline():
        print(f"  {entry.timestamp} [{entry.source.file_path}] {entry.message}")
```

## Supported Formats

| Format | Parser Name | Description |
|--------|-------------|-------------|
| JSON/JSONL | `json_structured` | JSON structured logs |
| Apache Combined | `apache_combined` | Apache Combined Log Format |
| Apache Common | `apache_common` | Apache Common Log Format |
| Nginx Access | `nginx_access` | Nginx default access log |
| Nginx Error | `nginx_error` | Nginx error log |
| Syslog RFC 3164 | `syslog_rfc3164` | BSD syslog format |
| Syslog RFC 5424 | `syslog_rfc5424` | Modern syslog format |
| Python Logging | `python_logging` | Python standard logging |
| Docker JSON | `docker_json` | Docker JSON log driver |
| Kubernetes | `kubernetes` | Kubernetes container logs |
| Generic | `generic` | Fallback for unknown formats |

## Output Formats

The CLI supports multiple output formats:

```bash
# Rich table (default)
ulp parse app.log

# JSON output
ulp parse --output json app.log

# CSV output
ulp parse --output csv app.log

# Compact single-line
ulp parse --output compact app.log
```

## Normalized Log Entry

All parsed logs are converted to a common `LogEntry` schema:

```python
LogEntry(
    # Core fields
    id: UUID,
    timestamp: datetime,
    level: LogLevel,
    message: str,
    raw: str,  # Original line

    # Structured data
    structured_data: dict,

    # Source metadata
    source: LogSource(
        file_path: str,
        line_number: int,
        hostname: str,
        service: str,
    ),

    # Network context (for access logs)
    network: NetworkInfo(
        source_ip: str,
        user_agent: str,
    ),

    # HTTP context (for web logs)
    http: HTTPInfo(
        method: str,
        path: str,
        status_code: int,
        response_size: int,
    ),

    # Correlation IDs
    correlation: CorrelationIds(
        request_id: str,
        trace_id: str,
        session_id: str,
    ),
)
```

## Architecture

ULP follows Clean Architecture principles:

```
src/ulp/
├── domain/          # Core entities and business rules
├── application/     # Use cases (parse, correlate)
├── infrastructure/  # Adapters (file sources, strategies)
├── parsers/         # Format-specific parsers
├── detection/       # Auto-detection logic
└── cli/             # Command-line interface
```

## Extending ULP

### Custom Parser

```python
from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel

class MyCustomParser(BaseParser):
    name = "my_format"
    formats = ["my_format"]

    def parse_line(self, line: str) -> LogEntry:
        # Parse your format
        return LogEntry(
            message=line,
            level=LogLevel.INFO,
        )

    def can_parse(self, sample_lines: list[str]) -> float:
        # Return confidence 0.0-1.0
        return 0.8 if self._looks_like_my_format(sample_lines) else 0.0
```

### Custom Normalization

```python
from ulp import NormalizationPipeline, TimestampNormalizer, LevelNormalizer

pipeline = NormalizationPipeline([
    TimestampNormalizer(target_tz="UTC"),
    LevelNormalizer(),
])

normalized_entry = pipeline.process_one(entry)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.
