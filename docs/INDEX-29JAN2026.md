# Universal Log Parser (ULP) Documentation

**Version:** 0.2.0
**Last Updated:** January 29, 2026

## Table of Contents

### Getting Started
- [Quick Start Guide](guides/QUICKSTART-29JAN2026.md)
- [Installation](guides/INSTALLATION-29JAN2026.md)
- [Basic Usage](guides/BASIC-USAGE-29JAN2026.md)

### User Guides
- [User Guide](guides/USER-GUIDE-29JAN2026.md) - Comprehensive usage documentation
- [CLI Reference](guides/CLI-REFERENCE-29JAN2026.md) - Complete CLI command reference
- [Streaming Large Files](guides/STREAMING-29JAN2026.md) - Working with 1-10GB+ files
- [Log Correlation](guides/CORRELATION-29JAN2026.md) - Cross-source log correlation

### API Reference
- [Public API](api/PUBLIC-API-29JAN2026.md) - Main public API functions
- [Core Models](api/MODELS-29JAN2026.md) - LogEntry, LogLevel, and data models
- [Domain Entities](api/ENTITIES-29JAN2026.md) - CorrelationGroup, CorrelationResult
- [Infrastructure](api/INFRASTRUCTURE-29JAN2026.md) - Sources, strategies, normalization

### Parser Reference
- [Supported Formats](reference/PARSERS-29JAN2026.md) - All supported log formats
- [Format Detection](reference/DETECTION-29JAN2026.md) - Auto-detection system
- [Creating Custom Parsers](reference/CUSTOM-PARSERS-29JAN2026.md)

### Architecture
- [Clean Architecture Overview](ARCHITECTURE-29JAN2026.md)
- [Design Principles](DESIGN-PRINCIPLES-29JAN2026.md)
- [Extension Guide](EXTENSIONS-29JAN2026.md)

### Examples
- [Common Use Cases](examples/COMMON-EXAMPLES-29JAN2026.md)
- [Advanced Examples](examples/ADVANCED-EXAMPLES-29JAN2026.md)
- [Integration Examples](examples/INTEGRATION-29JAN2026.md)

## Overview

Universal Log Parser (ULP) is a Python library and CLI tool that automatically detects, parses, and normalizes logs from any format. It's designed for production workloads with:

- **Auto-Detection**: Identifies 10+ log formats automatically
- **Streaming Support**: Memory-efficient parsing for files up to 10GB+
- **Log Correlation**: Correlate entries across multiple sources
- **Normalized Output**: Common schema for all log formats
- **Clean Architecture**: Domain-driven design with clear separation
- **Rich CLI**: Beautiful terminal output with multiple formats
- **Extensible**: Easy to add custom parsers and normalization

## Quick Example

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

## CLI Example

```bash
# Parse with auto-detection
ulp parse /var/log/nginx/access.log

# Filter by level and output as JSON
ulp parse --level error --output json app.log

# Stream large files (memory-efficient)
ulp stream --format json huge-file.log

# Correlate logs across multiple files
ulp correlate app.log nginx.log --strategy request_id
```

## Architecture

ULP follows Clean Architecture principles with clear layer separation:

```
src/ulp/
├── domain/          # Core entities and business rules
│   ├── entities.py  # LogEntry, CorrelationGroup, CorrelationResult
│   └── services.py  # Domain services and protocols
├── application/     # Use cases (orchestration)
│   ├── parse_logs.py       # Parsing use cases
│   └── correlate_logs.py   # Correlation use cases
├── infrastructure/  # Adapters and implementations
│   ├── sources/     # File, stdin, mmap sources
│   ├── correlation/ # Correlation strategies
│   └── normalization/ # Normalization pipeline
├── parsers/         # Format-specific parsers
│   ├── json_parser.py
│   ├── nginx.py
│   ├── apache.py
│   └── ...
├── detection/       # Format auto-detection
└── cli/             # Command-line interface
```

## Key Features

### Supported Log Formats

- JSON/JSONL structured logs
- Apache (Common and Combined)
- Nginx (Access and Error)
- Syslog (RFC 3164 and RFC 5424)
- Python logging
- Docker JSON logs
- Kubernetes container logs
- Generic fallback parser

### Normalized Schema

All logs are converted to a common `LogEntry` structure:

```python
LogEntry(
    timestamp: datetime,
    level: LogLevel,
    message: str,
    source: LogSource,
    network: NetworkInfo,  # For access logs
    http: HTTPInfo,        # For web logs
    correlation: CorrelationIds,  # For tracing
    structured_data: dict,
    extra: dict,
)
```

### Correlation Strategies

- **Request ID**: Group by request_id, trace_id, correlation_id
- **Timestamp Window**: Group by temporal proximity (1s window)
- **Session**: Group by user_id, session_id
- **Combined**: Use all strategies together

### Streaming Performance

ULP supports multiple streaming modes for large files:

- **FileStreamSource**: Standard line-by-line reading (<100MB)
- **LargeFileStreamSource**: Memory-mapped I/O (100MB-10GB+)
- **ChunkedFileStreamSource**: Progress tracking for large files
- **StdinStreamSource**: Real-time log streaming

## Documentation Conventions

Throughout this documentation:

- Code examples are fully functional and tested
- File paths are shown as absolute paths
- All API signatures include type hints
- Examples progress from simple to complex
- Performance characteristics are documented
- Memory usage is noted for large-scale operations

## Contributing

See the main repository README for contribution guidelines.

## License

MIT License - See LICENSE file for details.
