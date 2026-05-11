# Public API Reference

**Last Updated:** January 29, 2026

This document describes the main public API functions exported from the `ulp` package.

## Overview

The ULP public API is designed to be simple and intuitive. All main functions are exported from the top-level `ulp` module:

```python
from ulp import parse, detect_format, stream_parse, correlate
from ulp import LogEntry, LogLevel, CorrelationResult
```

## Core Functions

### `detect_format(file_path: str) -> tuple[str, float]`

Detect the log format of a file automatically.

**Parameters:**
- `file_path` (str): Path to the log file

**Returns:**
- `tuple[str, float]`: Format name and confidence score (0.0-1.0)

**Raises:**
- `FileNotFoundError`: If file doesn't exist
- `FormatDetectionError`: If unable to read file

**Example:**

```python
from ulp import detect_format

# Detect format
format_name, confidence = detect_format("/var/log/nginx/access.log")
print(f"Detected: {format_name} (confidence: {confidence:.0%})")
# Output: Detected: nginx_access (confidence: 95%)

# Low confidence indicates unknown format
format_name, confidence = detect_format("unknown.log")
if confidence < 0.5:
    print("Format unclear, will use generic parser")
```

**How it Works:**

The detector reads the first 50 lines of the file and:
1. Checks for JSON structure
2. Matches against regex patterns for known formats
3. Returns the best match with confidence score
4. Falls back to "generic" for unknown formats

---

### `parse(file_path: str, format: str | None = None) -> list[LogEntry]`

Parse a log file and return normalized LogEntry objects.

**Alias:** `parse_file()` - same function

**Parameters:**
- `file_path` (str): Path to the log file
- `format` (str | None): Optional format name to force specific parser

**Returns:**
- `list[LogEntry]`: List of normalized log entries

**Raises:**
- `FileNotFoundError`: If file doesn't exist
- `ParseError`: If parsing fails critically

**Example:**

```python
from ulp import parse, LogLevel

# Auto-detect format and parse
entries = parse("/var/log/app.log")

# Parse with specific format
entries = parse("access.log", format="nginx_access")

# Filter by level
errors = [e for e in entries if e.level >= LogLevel.ERROR]

# Access fields
for entry in errors:
    print(f"{entry.timestamp}: {entry.message}")
    if entry.http:
        print(f"  HTTP {entry.http.status_code} {entry.http.path}")
```

**Performance Notes:**

- Loads entire file into memory
- Suitable for files up to ~100MB
- For larger files, use `stream_parse()`
- Parsing speed: ~50,000-100,000 lines/second

---

### `stream_parse(file_path: str, format: str, progress_callback=None)`

Stream-parse a log file for minimal memory usage. Generator function.

**Parameters:**
- `file_path` (str): Path to the log file
- `format` (str): Format name (required - no auto-detection)
- `progress_callback` (callable | None): Optional callback(bytes_read, total_bytes, lines_read)

**Yields:**
- `LogEntry`: Entries as they are parsed

**Example:**

```python
from ulp import stream_parse, LogLevel

# Stream large file
for entry in stream_parse("huge.log", format="json"):
    if entry.level >= LogLevel.ERROR:
        print(f"{entry.timestamp}: {entry.message}")

# With progress tracking
def on_progress(bytes_read, total_bytes, lines_read):
    pct = bytes_read / total_bytes * 100
    print(f"\rProgress: {pct:.1f}% ({lines_read:,} lines)", end="")

for entry in stream_parse("huge.log", format="json", progress_callback=on_progress):
    process(entry)
```

**Performance Characteristics:**

- **Memory usage**: ~10-20MB regardless of file size
- **Speed**: ~100,000-200,000 lines/second
- **File size**: Tested up to 10GB
- **Streaming mode selection**:
  - Files <100MB: Standard line-by-line reading
  - Files >100MB: Memory-mapped I/O

**Why format is required:**

Auto-detection requires reading sample lines, which defeats streaming's memory efficiency. Specify the format explicitly for true streaming.

---

### `correlate(file_paths: list[str], strategy: str = "request_id", format: str | None = None, window_seconds: float = 1.0) -> CorrelationResult`

Correlate log entries across multiple files.

**Parameters:**
- `file_paths` (list[str]): List of log file paths
- `strategy` (str): Correlation strategy - one of:
  - `"request_id"`: Group by request_id/trace_id/correlation_id
  - `"timestamp"`: Group by temporal proximity
  - `"session"`: Group by session_id/user_id
  - `"all"`: Use all strategies
- `format` (str | None): Optional format name (auto-detect if not specified)
- `window_seconds` (float): Time window for timestamp correlation (default: 1.0)

**Returns:**
- `CorrelationResult`: Contains correlated groups and orphan entries

**Example:**

```python
from ulp import correlate

# Correlate by request ID
result = correlate(["app.log", "nginx.log"], strategy="request_id")

print(f"Found {len(result.groups)} correlation groups")
print(f"Statistics: {result.statistics}")

# Iterate through groups
for group in result.groups:
    print(f"\nRequest {group.correlation_key}:")
    print(f"  Entries: {len(group.entries)}")
    print(f"  Sources: {group.sources}")
    print(f"  Duration: {group.duration_ms()}ms")

    # View timeline
    for entry in group.timeline():
        source_file = entry.source.file_path.split('/')[-1]
        print(f"  [{source_file}] {entry.timestamp}: {entry.message}")

# Timestamp-based correlation
result = correlate(
    ["service-a.log", "service-b.log", "service-c.log"],
    strategy="timestamp",
    window_seconds=0.5  # 500ms window
)

# Combined strategies
result = correlate(
    ["app.log", "web.log", "db.log"],
    strategy="all"
)
```

**Correlation Result Structure:**

```python
CorrelationResult(
    groups: list[CorrelationGroup],
    orphan_entries: list[LogEntry],
    statistics: {
        "total_groups": int,
        "total_entries": int,
        "correlated_entries": int,
        "orphan_entries": int,
        "correlation_rate": float,  # 0.0-1.0
        "sources_covered": int,
        "avg_group_size": float,
    }
)
```

**Performance Notes:**

- Buffers entries in memory (window_size=10000)
- Suitable for analyzing related logs across microservices
- For very large files, consider pre-filtering by time range

---

## Convenience Re-exports

The following are also exported for convenience:

### Models

```python
from ulp import (
    LogEntry,
    LogLevel,
    LogSource,
    NetworkInfo,
    HTTPInfo,
    CorrelationIds,
    ParseResult,
)
```

See [Core Models](MODELS-29JAN2026.md) for details.

### Domain Entities

```python
from ulp import (
    CorrelationGroup,
    CorrelationResult,
)
```

See [Domain Entities](ENTITIES-29JAN2026.md) for details.

### Infrastructure Components

```python
from ulp import (
    # Sources
    FileStreamSource,
    LargeFileStreamSource,
    ChunkedFileStreamSource,
    StdinStreamSource,
    BufferedStdinSource,

    # Correlation strategies
    RequestIdCorrelation,
    TimestampWindowCorrelation,
    SessionCorrelation,

    # Normalization
    NormalizationPipeline,
    TimestampNormalizer,
    LevelNormalizer,
    FieldNormalizer,
)
```

See [Infrastructure](INFRASTRUCTURE-29JAN2026.md) for details.

### Parser Registry

```python
from ulp import registry, ParserRegistry

# List available parsers
parsers = registry.list_parsers()
formats = registry.list_formats()

# Get specific parser
parser = registry.get_parser("nginx_access")
```

### Exceptions

```python
from ulp import (
    ULPError,           # Base exception
    ParseError,         # Parsing failed
    FormatDetectionError,  # Detection failed
    ConfigurationError, # Invalid configuration
)
```

## Complete Example

Here's a comprehensive example using the public API:

```python
from ulp import (
    detect_format,
    parse,
    stream_parse,
    correlate,
    LogLevel,
    NormalizationPipeline,
    TimestampNormalizer,
    LevelNormalizer,
)

# Example 1: Parse and analyze a single file
print("=== Parsing access.log ===")
format_name, confidence = detect_format("access.log")
print(f"Format: {format_name} ({confidence:.0%})")

entries = parse("access.log")
print(f"Parsed {len(entries)} entries")

# Count by level
from collections import Counter
levels = Counter(e.level for e in entries)
print(f"Levels: {levels}")

# Find errors
errors = [e for e in entries if e.level >= LogLevel.ERROR]
print(f"Errors: {len(errors)}")
for error in errors[:5]:
    print(f"  {error.timestamp}: {error.message}")

# Example 2: Stream large file
print("\n=== Streaming huge.log ===")
error_count = 0
for entry in stream_parse("huge.log", format="json"):
    if entry.is_error():
        error_count += 1
        if error_count <= 10:
            print(f"Error: {entry.message}")

print(f"Total errors found: {error_count}")

# Example 3: Correlate multiple sources
print("\n=== Correlating logs ===")
result = correlate(
    ["app.log", "nginx.log", "db.log"],
    strategy="request_id"
)

print(f"Correlation statistics: {result.statistics}")

# Find requests that touched all three services
for group in result.groups:
    if len(group.sources) >= 3:
        print(f"\nMulti-service request {group.correlation_key}:")
        for entry in group.timeline():
            svc = entry.source.service or "unknown"
            print(f"  [{svc}] {entry.message}")

# Example 4: Custom normalization
print("\n=== Normalized parsing ===")
pipeline = NormalizationPipeline([
    TimestampNormalizer(target_tz="UTC"),
    LevelNormalizer(),
])

# Parse with normalization
from ulp.application.parse_logs import ParseLogsUseCase
from ulp.infrastructure import FileStreamSource
from ulp.infrastructure.adapters import (
    FormatDetectorAdapter,
    ParserRegistryAdapter,
)

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

## API Design Principles

The ULP public API follows these principles:

1. **Simple by default**: Common operations require minimal code
2. **Progressive disclosure**: Advanced features available when needed
3. **Type safety**: Full type hints for IDE support
4. **Fail gracefully**: Errors return partial results when possible
5. **Memory efficient**: Streaming APIs for large files
6. **Consistent naming**: Similar operations have similar names
7. **Composable**: Functions work well together

## Next Steps

- [Core Models Reference](MODELS-29JAN2026.md)
- [CLI Reference](../guides/CLI-REFERENCE-29JAN2026.md)
- [User Guide](../guides/USER-GUIDE-29JAN2026.md)
- [Common Examples](../examples/COMMON-EXAMPLES-29JAN2026.md)
