# Quick Start Guide

**Last Updated:** January 29, 2026

Get started with Universal Log Parser in 5 minutes.

## Installation

```bash
pip install ulp
```

Verify:

```bash
ulp --version
# Output: ulp, version 0.2.0
```

---

## 30-Second Tour

### Parse a log file

```bash
ulp parse /var/log/nginx/access.log
```

That's it! ULP automatically:
1. Detects the format (Nginx access log)
2. Parses all entries
3. Displays in a beautiful table

### Output

```
Detected nginx_access (confidence: 95%)

┌──────────────────────┬─────────┬─────────────────────────────┐
│ Timestamp            │ Level   │ Message                     │
├──────────────────────┼─────────┼─────────────────────────────┤
│ 2026-01-29 10:15:32  │ INFO    │ GET /api/users -> 200       │
│ 2026-01-29 10:15:33  │ WARNING │ GET /api/admin -> 403       │
│ 2026-01-29 10:15:34  │ ERROR   │ POST /api/order -> 500      │
└──────────────────────┴─────────┴─────────────────────────────┘
```

---

## Common Tasks

### 1. Find all errors

```bash
ulp parse --level error app.log
```

Shows only ERROR and above (CRITICAL, ALERT, EMERGENCY).

### 2. Search for patterns

```bash
ulp parse --grep "database.*timeout" app.log
```

Filters messages matching the regex pattern.

### 3. Export to JSON

```bash
ulp parse --output json app.log > output.json
```

Perfect for further processing with `jq` or other tools.

### 4. Process large files

```bash
ulp stream --format json huge-10gb.log
```

Uses constant memory regardless of file size.

### 5. Correlate across services

```bash
ulp correlate app.log nginx.log db.log --strategy request_id
```

Groups related logs by request ID across multiple files.

---

## Python API

### Basic Usage

```python
from ulp import parse, LogLevel

# Parse logs
entries = parse("app.log")

# Find errors
errors = [e for e in entries if e.level >= LogLevel.ERROR]

# Print details
for error in errors:
    print(f"{error.timestamp}: {error.message}")
```

### Streaming

```python
from ulp import stream_parse

# Stream large file
for entry in stream_parse("huge.log", format="json"):
    if entry.is_error():
        print(entry.message)
```

### Correlation

```python
from ulp import correlate

result = correlate(["app.log", "web.log"], strategy="request_id")

for group in result.groups:
    print(f"Request {group.correlation_key}: {len(group.entries)} logs")
    for entry in group.timeline():
        print(f"  {entry.timestamp}: {entry.message}")
```

---

## Supported Formats

ULP auto-detects these formats:

- **JSON/JSONL** - Structured application logs
- **Nginx** - Access and error logs
- **Apache** - Common and combined formats
- **Syslog** - RFC 3164 and RFC 5424
- **Docker** - JSON and daemon logs
- **Kubernetes** - Container, component, audit logs
- **Python** - Standard logging module output
- **Generic** - Fallback for unknown formats

Check all formats:

```bash
ulp formats
```

---

## Key Features

### Auto-Detection

```bash
# No need to specify format
ulp parse mystery.log

# But you can if you want
ulp parse --format json_structured app.log
```

### Streaming Performance

```bash
# Handle 10GB+ files with ~10MB memory
ulp stream --format docker_json huge-container.log
```

### Cross-Source Correlation

```bash
# Track requests across microservices
ulp correlate api.log gateway.log database.log
```

### Flexible Output

```bash
# Table (default) - human-readable
ulp parse app.log

# JSON - for scripting
ulp parse --output json app.log | jq '.[] | select(.level == "ERROR")'

# CSV - for spreadsheets
ulp parse --output csv app.log > data.csv

# Compact - for piping
ulp parse --output compact app.log | grep ERROR
```

---

## Examples

### Monitor logs in real-time

```bash
tail -f /var/log/app.log | ulp parse --format json --level error
```

### Find slow requests

```bash
ulp parse nginx-access.log --output json \
  | jq '.[] | select(.http.response_time_ms > 1000)'
```

### Count errors by hour

```bash
ulp parse --level error app.log --output json \
  | jq -r '.timestamp' \
  | cut -d'T' -f2 \
  | cut -d':' -f1 \
  | sort | uniq -c
```

### Debug a request across services

```python
from ulp import correlate

result = correlate(
    ["gateway.log", "auth.log", "api.log", "db.log"],
    strategy="request_id"
)

# Find the problematic request
for group in result.groups:
    if any(e.level.name == "ERROR" for e in group.entries):
        print(f"\nFailed request: {group.correlation_key}")
        for entry in group.timeline():
            svc = entry.source.service or "unknown"
            level = entry.level.name
            print(f"  [{svc:10}] {level:8} {entry.message}")
```

Output:

```
Failed request: req-abc123

  [gateway   ] INFO     Request received: POST /api/order
  [auth      ] INFO     Authentication successful for user_id=42
  [api       ] INFO     Processing order
  [db        ] ERROR    Connection timeout after 30s
  [api       ] ERROR    Order creation failed
  [gateway   ] ERROR    500 Internal Server Error
```

---

## Tips

1. **Always use streaming for large files** (>100MB)
   ```bash
   ulp stream --format json huge.log
   ```

2. **Specify format in production** (faster than auto-detect)
   ```bash
   ulp parse --format json_structured app.log
   ```

3. **Use JSON output for scripting**
   ```bash
   ulp parse app.log --output json | jq '...'
   ```

4. **Correlate for debugging distributed systems**
   ```bash
   ulp correlate *.log --strategy request_id
   ```

5. **Filter early for better performance**
   ```bash
   ulp parse --level error app.log  # Faster than filtering after
   ```

---

## What's Next?

### Learn More

- [User Guide](USER-GUIDE-29JAN2026.md) - Comprehensive usage guide
- [CLI Reference](CLI-REFERENCE-29JAN2026.md) - All CLI commands
- [API Reference](../api/PUBLIC-API-29JAN2026.md) - Python API
- [Parser Reference](../reference/PARSERS-29JAN2026.md) - Supported formats

### Advanced Topics

- [Architecture](../ARCHITECTURE-29JAN2026.md) - System design
- [Custom Parsers](../reference/CUSTOM-PARSERS-29JAN2026.md) - Extend ULP
- [Examples](../examples/COMMON-EXAMPLES-29JAN2026.md) - Practical examples

### Get Help

- Check [Troubleshooting](USER-GUIDE-29JAN2026.md#troubleshooting) section
- Report issues on GitHub
- Read the source code (it's clean architecture!)

---

## Common Patterns

### Error Analysis

```bash
# Count errors
ulp parse --level error app.log | wc -l

# Group by error type
ulp parse --level error app.log --output json \
  | jq -r '.message' | sort | uniq -c | sort -rn

# Find error clusters by time
ulp parse --level error app.log --output json \
  | jq -r '.timestamp' | cut -d'T' -f1,2 | cut -d':' -f1,2 | uniq -c
```

### Performance Analysis

```bash
# Find slowest endpoints
ulp parse nginx-access.log --output json \
  | jq -r '"\(.http.response_time_ms)\t\(.http.path)"' \
  | sort -rn | head -20

# Response time percentiles
ulp parse nginx-access.log --output json \
  | jq -r '.http.response_time_ms' \
  | sort -n \
  | awk '{a[NR]=$1} END{print "p50:",a[int(NR*0.5)], "p95:",a[int(NR*0.95)], "p99:",a[int(NR*0.99)]}'
```

### Security Analysis

```bash
# Find failed login attempts
ulp parse auth.log --grep "failed.*login" --output json

# Top suspicious IPs (many 403s)
ulp parse access.log --output json \
  | jq -r 'select(.http.status_code == 403) | .network.source_ip' \
  | sort | uniq -c | sort -rn | head -10

# Unusual user agents
ulp parse access.log --output json \
  | jq -r '.network.user_agent' \
  | sort | uniq -c | sort -rn | tail -20
```

---

## That's It!

You're now ready to parse logs like a pro. ULP handles the complexity of different log formats so you can focus on analyzing the data.

**Happy log parsing!** 🚀
