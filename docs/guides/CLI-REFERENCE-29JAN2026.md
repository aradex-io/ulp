# CLI Reference

**Last Updated:** January 29, 2026

Complete reference for the `ulp` command-line interface.

## Overview

The ULP CLI provides powerful log parsing and analysis capabilities directly from the terminal with beautiful output formatting powered by Rich.

```bash
ulp --help
```

## Global Options

Available for all commands:

- `--quiet`, `-q`: Suppress non-essential output
- `--version`: Show version and exit
- `--help`: Show help message and exit

## Commands

### `ulp parse`

Parse log files and display normalized output.

**Synopsis:**

```bash
ulp parse [OPTIONS] [FILES]...
```

**Arguments:**

- `FILES`: One or more log files to parse (optional - reads from stdin if not specified)

**Options:**

- `--format`, `-f FORMAT`: Force a specific log format (skip auto-detection)
- `--output`, `-o FORMAT`: Output format - `table` (default), `json`, `csv`, `compact`
- `--level`, `-l LEVEL`: Filter by minimum log level - `debug`, `info`, `warning`, `error`, `critical`
- `--limit`, `-n N`: Limit number of entries to display
- `--grep`, `-g PATTERN`: Filter entries by message content (regex)
- `--normalize/--no-normalize`: Apply normalization pipeline (timestamps to UTC, level normalization)

**Examples:**

```bash
# Parse with auto-detection (default table output)
ulp parse /var/log/nginx/access.log

# Parse multiple files
ulp parse app.log api.log worker.log

# Force specific format
ulp parse --format json_structured app.log

# Filter by level and output as JSON
ulp parse --level error --output json app.log

# Filter with regex pattern
ulp parse --grep "user.*login" auth.log
ulp parse --grep "(ERROR|WARN)" app.log

# Limit output
ulp parse --limit 100 app.log

# Normalize timestamps to UTC
ulp parse --normalize app.log

# Combine multiple options
ulp parse --format nginx_access --level warning --limit 50 --output json access.log

# Read from stdin
tail -f /var/log/app.log | ulp parse --format json

# Parse compressed files (using process substitution)
ulp parse <(zcat access.log.gz)
```

**Output Formats:**

1. **table** (default): Rich formatted table with columns
   ```
   ┌──────────────────────┬─────────┬────────────────────────────────┐
   │ Timestamp            │ Level   │ Message                        │
   ├──────────────────────┼─────────┼────────────────────────────────┤
   │ 2026-01-29 10:15:32  │ INFO    │ Request processed successfully │
   │ 2026-01-29 10:15:33  │ ERROR   │ Database connection failed     │
   └──────────────────────┴─────────┴────────────────────────────────┘
   ```

2. **json**: JSON array of log entries
   ```json
   [
     {
       "id": "uuid-here",
       "timestamp": "2026-01-29T10:15:32Z",
       "level": "INFO",
       "message": "Request processed",
       "http": {
         "method": "GET",
         "status_code": 200
       }
     }
   ]
   ```

3. **csv**: CSV format for spreadsheet import
   ```csv
   timestamp,level,message,source_ip,status_code
   2026-01-29 10:15:32,INFO,Request processed,192.168.1.1,200
   ```

4. **compact**: Single-line format for piping
   ```
   10:15:32 INFO  Request processed
   10:15:33 ERROR Database connection failed
   ```

**Exit Codes:**

- `0`: Success
- `1`: Error (file not found, parse error, etc.)

---

### `ulp detect`

Detect the log format of files without parsing.

**Synopsis:**

```bash
ulp detect [OPTIONS] FILES...
```

**Arguments:**

- `FILES`: One or more log files to analyze (required)

**Options:**

- `--all`, `-a`: Show all matching formats with confidence scores

**Examples:**

```bash
# Detect single file
ulp detect /var/log/nginx/access.log
# Output: access.log: nginx_access ██████████ 95%

# Detect multiple files
ulp detect /var/log/*.log

# Show all potential matches
ulp detect --all app.log
# Output:
# app.log
#   json_structured  ██████████ 95%
#   generic          ████░░░░░░ 40%
#   python_logging   ██░░░░░░░░ 20%

# Batch detection
find /var/log -name "*.log" | xargs ulp detect
```

**Output:**

Shows format name and confidence as a visual bar:

- Green (≥80%): High confidence
- Yellow (50-79%): Medium confidence
- Red (<50%): Low confidence

**Use Cases:**

- Verify log format before batch processing
- Discover unknown log files
- Validate parser accuracy

---

### `ulp correlate`

Correlate logs across multiple files by request ID, timestamp, or session.

**Synopsis:**

```bash
ulp correlate [OPTIONS] FILES...
```

**Arguments:**

- `FILES`: Two or more log files to correlate (required, minimum 2)

**Options:**

- `--format`, `-f FORMAT`: Force a specific log format for all files
- `--strategy`, `-s STRATEGY`: Correlation strategy - `request_id` (default), `timestamp`, `session`, `all`
- `--window`, `-w SECONDS`: Time window in seconds for timestamp correlation (default: 1.0)
- `--output`, `-o FORMAT`: Output format - `table` (default), `json`

**Examples:**

```bash
# Correlate by request ID
ulp correlate app.log nginx.log db.log

# Use timestamp-based correlation
ulp correlate --strategy timestamp app.log web.log

# Narrow time window to 500ms
ulp correlate --strategy timestamp --window 0.5 service-a.log service-b.log

# Session-based correlation
ulp correlate --strategy session app.log auth.log

# Use all strategies
ulp correlate --strategy all app.log nginx.log db.log redis.log

# JSON output for processing
ulp correlate --output json app.log web.log | jq '.groups[0]'

# Specific format for all files
ulp correlate --format json_structured *.log
```

**Output:**

Table format shows correlation groups:

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

JSON format provides detailed structure:

```json
{
  "groups": [
    {
      "id": "uuid",
      "correlation_key": "req-abc123",
      "correlation_type": "request_id",
      "entry_count": 8,
      "sources": ["app.log", "nginx.log", "db.log"],
      "time_range": ["2026-01-29T10:15:32Z", "2026-01-29T10:15:33Z"]
    }
  ],
  "orphan_count": 123
}
```

**Correlation Strategies:**

1. **request_id**: Groups entries with same request_id, trace_id, correlation_id, or transaction_id
   - Most reliable when IDs are present
   - Works across different log formats
   - Ideal for microservices with distributed tracing

2. **timestamp**: Groups entries within a time window
   - Useful when no explicit IDs exist
   - Configurable window (default 1 second)
   - Best for related operations that happen together

3. **session**: Groups by session_id or user_id
   - Tracks user sessions across requests
   - Handles session timeouts (default 30 minutes)
   - Good for analyzing user behavior

4. **all**: Applies all strategies, creating multiple group types

**Performance:**

- Buffers up to 10,000 entries in memory
- Suitable for moderate-sized log files
- For large files, consider pre-filtering by time range

---

### `ulp stream`

Stream-parse very large log files (1-10GB+) with minimal memory usage.

**Synopsis:**

```bash
ulp stream [OPTIONS] FILE
```

**Arguments:**

- `FILE`: Log file to stream (required)

**Options:**

- `--format`, `-f FORMAT`: Log format (required - no auto-detection in stream mode)
- `--output`, `-o FORMAT`: Output format - `compact` (default), `json`
- `--progress/--no-progress`: Show progress indicator (default: on)

**Examples:**

```bash
# Stream large file
ulp stream --format docker_json huge-container.log

# JSON output for piping
ulp stream --format json app.log --output json | jq -r '.message'

# No progress indicator
ulp stream --format syslog_rfc3164 /var/log/messages --no-progress

# Stream and filter with grep
ulp stream --format json app.log | grep ERROR

# Count errors in large file
ulp stream --format json app.log --output json | jq -r '.level' | grep ERROR | wc -l

# Extract specific fields
ulp stream --format nginx_access access.log --output json | jq -r '"\(.timestamp) \(.http.status_code) \(.http.path)"'
```

**Why Stream Mode?**

Regular `ulp parse` loads the entire file into memory. For files >100MB, this becomes inefficient. Stream mode:

- Uses constant memory (~10-20MB)
- Processes files of any size
- Uses memory-mapped I/O for files >100MB
- Shows progress for long operations

**Limitations:**

- Format must be specified (no auto-detection)
- Output is immediate (no sorting by timestamp)
- Cannot use features that require all entries (like correlation)

**Performance:**

- Speed: ~100,000-200,000 lines/second
- Memory: ~10-20MB regardless of file size
- Tested with files up to 10GB

---

### `ulp formats`

List all supported log formats and their parsers.

**Synopsis:**

```bash
ulp formats
```

**Example:**

```bash
ulp formats
```

**Output:**

```
┌─────────────────────┬──────────────────────────────────────────────┐
│ Parser              │ Formats                                      │
├─────────────────────┼──────────────────────────────────────────────┤
│ apache_combined     │ apache_combined, combined                    │
│ apache_common       │ apache_common, common, clf                   │
│ docker_daemon       │ docker_daemon                                │
│ docker_json         │ docker_json, docker                          │
│ generic             │ generic, unknown                             │
│ json                │ json, jsonl, json_structured                 │
│ kubernetes_audit    │ k8s_audit, kubernetes_audit                  │
│ kubernetes_component│ k8s_component, kubernetes_component          │
│ kubernetes_container│ k8s_container, kubernetes_container          │
│ kubernetes_event    │ k8s_event, kubernetes_event                  │
│ nginx_access        │ nginx_access, nginx_default, nginx           │
│ nginx_error         │ nginx_error                                  │
│ python_logging      │ python, python_logging                       │
│ syslog_rfc3164      │ syslog, syslog_rfc3164, bsd_syslog           │
│ syslog_rfc5424      │ syslog_rfc5424, modern_syslog                │
└─────────────────────┴──────────────────────────────────────────────┘
```

**Use Case:**

Check format names for use with `--format` option.

---

## Environment Variables

None currently. Configuration is command-line only.

---

## Exit Codes

All commands use standard exit codes:

- `0`: Success
- `1`: Error (file not found, parse error, invalid arguments)

---

## Shell Completion

ULP uses Click, which supports shell completion:

### Bash

```bash
# Add to ~/.bashrc
eval "$(_ULP_COMPLETE=bash_source ulp)"
```

### Zsh

```bash
# Add to ~/.zshrc
eval "$(_ULP_COMPLETE=zsh_source ulp)"
```

### Fish

```bash
# Add to ~/.config/fish/completions/ulp.fish
eval (env _ULP_COMPLETE=fish_source ulp)
```

---

## Pipeline Examples

### Example 1: Monitor logs in real-time

```bash
# Monitor and filter errors
tail -f /var/log/app.log | ulp parse --format json --level error

# Watch specific pattern
tail -f access.log | ulp parse --format nginx_access --grep "POST /api"
```

### Example 2: Analyze historical logs

```bash
# Count errors by hour
ulp parse --format json --level error app.log --output json \
  | jq -r '.timestamp' \
  | cut -d'T' -f2 \
  | cut -d':' -f1 \
  | sort | uniq -c

# Top IP addresses
ulp parse access.log --output json \
  | jq -r '.network.source_ip' \
  | sort | uniq -c | sort -rn | head -10

# Response time percentiles
ulp parse nginx-access.log --output json \
  | jq -r '.http.response_time_ms' \
  | sort -n \
  | awk '{a[NR]=$1} END{print "p50:",a[int(NR*0.5)], "p95:",a[int(NR*0.95)], "p99:",a[int(NR*0.99)]}'
```

### Example 3: Convert formats

```bash
# Nginx to JSON
ulp parse access.log --format nginx_access --output json > access.json

# Multiple files to CSV
ulp parse *.log --output csv > combined.csv

# Compressed logs to JSON
zcat app.log.gz | ulp parse --format json --output json > app-parsed.json
```

### Example 4: Correlation analysis

```bash
# Find slow requests across services
ulp correlate app.log nginx.log --strategy request_id --output json \
  | jq '.groups[] | select(.duration_ms > 1000)'

# Session analysis
ulp correlate app.log auth.log --strategy session --output json \
  | jq -r '.groups[] | "\(.correlation_key): \(.entry_count) events"'
```

---

## Troubleshooting

### "Format not detected with high confidence"

```bash
# Check detection
ulp detect --all myfile.log

# Force format if you know it
ulp parse --format generic myfile.log
```

### "Memory error with large file"

```bash
# Use streaming instead of parse
ulp stream --format json huge.log
```

### "Invalid regex pattern"

```bash
# Escape special characters
ulp parse --grep "error\\.log" app.log

# Use quotes for complex patterns
ulp parse --grep "(ERROR|WARN|FATAL)" app.log
```

### "No output appears"

```bash
# Check if filtering too much
ulp parse --level debug app.log  # Lower level threshold

# Check if file is empty
wc -l app.log

# Try quiet mode off
ulp parse app.log  # Don't use --quiet
```

---

## Tips and Best Practices

1. **Use stream mode for large files**: Files >100MB should use `ulp stream`

2. **Leverage stdin**: Combine with other tools via pipes
   ```bash
   zcat logs.gz | ulp parse --format json
   ```

3. **JSON output for processing**: Use `--output json` with `jq`
   ```bash
   ulp parse app.log --output json | jq '.[] | select(.level == "ERROR")'
   ```

4. **Format detection first**: Run `ulp detect` before batch processing
   ```bash
   ulp detect *.log
   ulp parse --format json_structured *.log
   ```

5. **Correlation for debugging**: Track requests across microservices
   ```bash
   ulp correlate app.log gateway.log database.log --strategy request_id
   ```

---

## Next Steps

- [User Guide](USER-GUIDE-29JAN2026.md)
- [Public API](../api/PUBLIC-API-29JAN2026.md)
- [Common Examples](../examples/COMMON-EXAMPLES-29JAN2026.md)
