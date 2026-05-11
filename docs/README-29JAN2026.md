# Universal Log Parser Documentation

**Version:** 0.2.0
**Last Updated:** January 29, 2026

Welcome to the comprehensive documentation for Universal Log Parser (ULP).

## Documentation Structure

### Getting Started

Start here if you're new to ULP:

1. **[Quick Start](guides/QUICKSTART-29JAN2026.md)** (5 minutes)
   - Installation
   - Basic usage examples
   - Common patterns
   - Get productive immediately

2. **[User Guide](guides/USER-GUIDE-29JAN2026.md)** (Full reference)
   - Complete usage documentation
   - All features explained
   - Best practices
   - Troubleshooting

### Command-Line Interface

3. **[CLI Reference](guides/CLI-REFERENCE-29JAN2026.md)**
   - Complete command reference
   - All options and flags
   - Pipeline examples
   - Shell completion

### Python API

4. **[Public API](api/PUBLIC-API-29JAN2026.md)**
   - Main API functions
   - `parse()`, `stream_parse()`, `correlate()`, `detect_format()`
   - Examples and use cases

5. **[Core Models](api/MODELS-29JAN2026.md)**
   - `LogEntry` structure
   - `LogLevel` enumeration
   - Supporting models (LogSource, HTTPInfo, NetworkInfo, CorrelationIds)
   - Serialization

6. **[Domain Entities](api/ENTITIES-29JAN2026.md)**
   - `CorrelationGroup` and `CorrelationResult`
   - Domain services and protocols
   - Business logic entities

7. **[Infrastructure](api/INFRASTRUCTURE-29JAN2026.md)**
   - Sources (file, stdin, streaming)
   - Correlation strategies
   - Normalization pipeline
   - Adapters

### Log Formats

8. **[Supported Formats](reference/PARSERS-29JAN2026.md)**
   - Complete parser reference
   - Format examples
   - Field mappings
   - Detection confidence

9. **[Format Detection](reference/DETECTION-29JAN2026.md)**
   - Auto-detection system
   - Confidence scoring
   - Format signatures

10. **[Custom Parsers](reference/CUSTOM-PARSERS-29JAN2026.md)**
    - Creating custom parsers
    - Parser API
    - Registration
    - Testing

### Architecture

11. **[Architecture Overview](ARCHITECTURE-29JAN2026.md)**
    - Clean Architecture design
    - Layer structure
    - Dependency flow
    - Design patterns
    - Extension points

12. **[Design Principles](DESIGN-PRINCIPLES-29JAN2026.md)**
    - Domain-Driven Design
    - SOLID principles
    - Architectural decisions
    - Rationale

13. **[Extensions Guide](EXTENSIONS-29JAN2026.md)**
    - Adding custom parsers
    - Custom correlation strategies
    - Custom normalization steps
    - Plugin development

### Examples

14. **[Common Examples](examples/COMMON-EXAMPLES-29JAN2026.md)**
    - Basic parsing
    - Filtering and searching
    - Correlation workflows
    - Output formatting

15. **[Advanced Examples](examples/ADVANCED-EXAMPLES-29JAN2026.md)**
    - Batch processing
    - Custom normalization
    - Integration patterns
    - Performance optimization

16. **[Integration Examples](examples/INTEGRATION-29JAN2026.md)**
    - Monitoring system integration
    - Data pipeline integration
    - CI/CD integration
    - Real-world use cases

---

## Quick Navigation

### By Role

**For DevOps/SRE:**
- Start with [Quick Start](guides/QUICKSTART-29JAN2026.md)
- Learn [CLI Reference](guides/CLI-REFERENCE-29JAN2026.md)
- Use [Parser Reference](reference/PARSERS-29JAN2026.md) to identify formats

**For Python Developers:**
- Read [Public API](api/PUBLIC-API-29JAN2026.md)
- Understand [Core Models](api/MODELS-29JAN2026.md)
- Explore [Examples](examples/COMMON-EXAMPLES-29JAN2026.md)

**For Architects:**
- Review [Architecture Overview](ARCHITECTURE-29JAN2026.md)
- Study [Design Principles](DESIGN-PRINCIPLES-29JAN2026.md)
- Check [Extensions Guide](EXTENSIONS-29JAN2026.md)

**For Contributors:**
- Understand [Architecture](ARCHITECTURE-29JAN2026.md)
- Read [Custom Parsers](reference/CUSTOM-PARSERS-29JAN2026.md)
- Review source code (clean architecture!)

### By Task

**Parse logs:**
- [Quick Start - Parse a log file](guides/QUICKSTART-29JAN2026.md#30-second-tour)
- [User Guide - Parsing Logs](guides/USER-GUIDE-29JAN2026.md#parsing-logs)
- [CLI Reference - ulp parse](guides/CLI-REFERENCE-29JAN2026.md#ulp-parse)

**Handle large files:**
- [User Guide - Streaming](guides/USER-GUIDE-29JAN2026.md#streaming-large-files)
- [CLI Reference - ulp stream](guides/CLI-REFERENCE-29JAN2026.md#ulp-stream)
- [Public API - stream_parse()](api/PUBLIC-API-29JAN2026.md#stream_parsefile_path-str-format-str-progress_callbacknone)

**Correlate logs:**
- [User Guide - Correlation](guides/USER-GUIDE-29JAN2026.md#log-correlation)
- [CLI Reference - ulp correlate](guides/CLI-REFERENCE-29JAN2026.md#ulp-correlate)
- [Public API - correlate()](api/PUBLIC-API-29JAN2026.md#correlatefile_paths-liststr-strategy-str--request_id-format-str--none-none-window_seconds-float--10--correlationresult)

**Detect format:**
- [Parser Reference - Detection](reference/PARSERS-29JAN2026.md#format-detection)
- [CLI Reference - ulp detect](guides/CLI-REFERENCE-29JAN2026.md#ulp-detect)
- [Public API - detect_format()](api/PUBLIC-API-29JAN2026.md#detect_formatfile_path-str---tuplestr-float)

**Create custom parser:**
- [Custom Parsers Guide](reference/CUSTOM-PARSERS-29JAN2026.md)
- [Extensions Guide](EXTENSIONS-29JAN2026.md#adding-a-custom-parser)
- [Architecture - Parsers Layer](ARCHITECTURE-29JAN2026.md#parsers-layer)

---

## Documentation Overview

### What is ULP?

Universal Log Parser (ULP) is a Python library and CLI tool that:

1. **Automatically detects** log formats (10+ formats supported)
2. **Parses** logs into a normalized structure
3. **Streams** large files (1-10GB+) efficiently
4. **Correlates** logs across multiple sources
5. **Exports** in multiple formats (JSON, CSV, table)

### Key Concepts

#### Normalized LogEntry

All logs are converted to a common `LogEntry` structure:

```python
LogEntry(
    timestamp: datetime,
    level: LogLevel,
    message: str,
    source: LogSource,
    http: HTTPInfo,           # For web logs
    network: NetworkInfo,     # For access logs
    correlation: CorrelationIds,  # For tracing
    structured_data: dict,
)
```

#### Clean Architecture

ULP follows Clean Architecture with clear layers:

```
Domain → Application → Infrastructure
  ↑          ↑              ↑
  └──────────┴──────────────┘
     Core business logic
```

#### Streaming Support

Three streaming modes:

1. **FileStreamSource**: Standard reading (<100MB)
2. **LargeFileStreamSource**: Memory-mapped I/O (100MB-10GB+)
3. **ChunkedFileStreamSource**: Progress tracking

#### Correlation Strategies

Three ways to correlate logs:

1. **Request ID**: Group by request_id/trace_id
2. **Timestamp**: Group by temporal proximity
3. **Session**: Group by session_id/user_id

---

## Supported Log Formats

| Format | Example | Detection |
|--------|---------|-----------|
| JSON/JSONL | `{"level":"ERROR","message":"..."}` | High |
| Apache Combined | `192.168.1.1 - - [29/Jan/2026:10:15:32] "GET /"` | High |
| Nginx Access | Same as Apache Combined | High |
| Nginx Error | `2026/01/29 10:15:32 [error] 1234#5678: ...` | High |
| Syslog RFC 3164 | `Jan 29 10:15:32 host app[123]: ...` | Medium |
| Syslog RFC 5424 | `<34>1 2026-01-29T10:15:32Z host app ...` | High |
| Python Logging | `INFO:myapp:Message` | Medium |
| Docker JSON | `{"log":"...\n","stream":"stdout","time":"..."}` | High |
| Kubernetes | Container, component, audit, event logs | High |
| Generic | Any unknown format | Low |

See [Parser Reference](reference/PARSERS-29JAN2026.md) for details.

---

## Quick Reference

### CLI Commands

```bash
# Parse logs
ulp parse app.log
ulp parse --format json --level error app.log

# Detect format
ulp detect app.log
ulp detect --all *.log

# Stream large files
ulp stream --format json huge.log

# Correlate logs
ulp correlate app.log web.log --strategy request_id

# List formats
ulp formats
```

### Python API

```python
from ulp import parse, detect_format, stream_parse, correlate

# Detect
format_name, confidence = detect_format("app.log")

# Parse
entries = parse("app.log")
entries = parse("app.log", format="json")

# Stream
for entry in stream_parse("huge.log", format="json"):
    process(entry)

# Correlate
result = correlate(["app.log", "web.log"], strategy="request_id")
```

---

## Installation

```bash
# Basic
pip install ulp

# With optional dependencies
pip install ulp[geoip]      # GeoIP enrichment
pip install ulp[benchmark]  # Benchmarking
pip install ulp[all]        # Everything
```

---

## Contributing

See the main repository README for contribution guidelines.

### Documentation Contributions

- Documentation is in Markdown format
- Follow existing structure and style
- Include code examples
- Test all examples
- Add dates to filenames (e.g., `GUIDE-29JAN2026.md`)

---

## Documentation Conventions

Throughout this documentation:

- **Code blocks** are fully functional and tested
- **File paths** are absolute paths
- **Type hints** are included in Python examples
- **Examples** progress from simple to complex
- **Performance** characteristics are documented where relevant
- **Memory usage** is noted for large-scale operations
- **Dates** are included in filenames per project conventions

---

## Version History

### v0.2.0 (Current)

- Streaming support for large files (1-10GB+)
- Cross-source log correlation
- Normalization pipeline
- Additional parsers (Docker, Kubernetes)
- Clean Architecture refactoring

### v0.1.0

- Initial release
- Basic parsing and detection
- JSON, Apache, Nginx, Syslog parsers
- CLI interface

---

## Getting Help

1. **Check the docs**: Search this documentation
2. **Read examples**: See [Common Examples](examples/COMMON-EXAMPLES-29JAN2026.md)
3. **Troubleshooting**: See [User Guide - Troubleshooting](guides/USER-GUIDE-29JAN2026.md#troubleshooting)
4. **Report issues**: GitHub issues
5. **Read source**: Clean architecture makes it readable!

---

## License

MIT License - See LICENSE file for details.

---

## About This Documentation

**Generated:** January 29, 2026
**ULP Version:** 0.2.0
**Format:** Markdown
**Location:** `/docs/` directory

All documentation follows project conventions with dates in filenames per the project's CLAUDE.md guidelines.

---

## Document Index

### Guides
- [INDEX-29JAN2026.md](INDEX-29JAN2026.md) - Main index
- [guides/QUICKSTART-29JAN2026.md](guides/QUICKSTART-29JAN2026.md) - 5-minute quick start
- [guides/USER-GUIDE-29JAN2026.md](guides/USER-GUIDE-29JAN2026.md) - Comprehensive user guide
- [guides/CLI-REFERENCE-29JAN2026.md](guides/CLI-REFERENCE-29JAN2026.md) - CLI command reference

### API Documentation
- [api/PUBLIC-API-29JAN2026.md](api/PUBLIC-API-29JAN2026.md) - Public API functions
- [api/MODELS-29JAN2026.md](api/MODELS-29JAN2026.md) - Core data models
- [api/ENTITIES-29JAN2026.md](api/ENTITIES-29JAN2026.md) - Domain entities
- [api/INFRASTRUCTURE-29JAN2026.md](api/INFRASTRUCTURE-29JAN2026.md) - Infrastructure layer

### Reference
- [reference/PARSERS-29JAN2026.md](reference/PARSERS-29JAN2026.md) - Supported formats
- [reference/DETECTION-29JAN2026.md](reference/DETECTION-29JAN2026.md) - Format detection
- [reference/CUSTOM-PARSERS-29JAN2026.md](reference/CUSTOM-PARSERS-29JAN2026.md) - Custom parsers

### Architecture
- [ARCHITECTURE-29JAN2026.md](ARCHITECTURE-29JAN2026.md) - Architecture overview
- [DESIGN-PRINCIPLES-29JAN2026.md](DESIGN-PRINCIPLES-29JAN2026.md) - Design principles
- [EXTENSIONS-29JAN2026.md](EXTENSIONS-29JAN2026.md) - Extension guide

### Examples
- [examples/COMMON-EXAMPLES-29JAN2026.md](examples/COMMON-EXAMPLES-29JAN2026.md) - Common use cases
- [examples/ADVANCED-EXAMPLES-29JAN2026.md](examples/ADVANCED-EXAMPLES-29JAN2026.md) - Advanced examples
- [examples/INTEGRATION-29JAN2026.md](examples/INTEGRATION-29JAN2026.md) - Integration examples

---

**Happy log parsing with ULP!** 🚀
