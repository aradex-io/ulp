# ULP 0.2.0 — Phased Application Review: Findings Report

**Review subject:** Universal Log Parser (ULP), version 0.2.0
**Source under review:** `jeremylaratro/ulp-e2590588 @ source/main` (imported as the baseline commit of this branch)
**Review branch:** `claude/app-review-findings-55ErI`
**Date:** 2026-05-11
**Methodology:** Two-phase review. Phase 1 planning by Opus (scope partitioning, file ownership, severity rubric, reporting contract). Phase 2 execution by six Sonnet agents working in parallel across non-overlapping scopes (security, parser correctness, application/domain, infrastructure/streaming, CLI/display, tests/packaging/CI/docs). Phase 3 consolidation by Opus (deduplication, severity reconciliation, executive summary).

---

## Executive summary

ULP is a Python 3.10+ log-parsing library and CLI (~6,100 LOC) that claims to parse 10+ formats, stream 1–10 GB files via memory-mapped I/O, and correlate logs across sources. The product surface is well organized along clean-architecture lines, and several hardening controls are in place (CSV sanitization, JSON depth limit, per-line length cap, correlation-bound constants). However, **multiple advertised features are demonstrably broken or unsafe at their core implementation**:

- The mmap streaming path — the single most-advertised feature — combines three defects (crash on empty/rotated file, O(n) byte-by-byte Python loop, and unbounded buffer accumulation that bypasses the line-length cap) that together make "streaming 10 GB files" effectively unusable AND unsafe.
- The normalization pipeline's default error-recovery path is itself broken (`AttributeError` on `entry.metadata`), so `stop_on_error=False` raises on the first error.
- `LogEntry.from_dict` raises raw `KeyError` (not a `ULPError`) on any unfamiliar level name — including levels the library's own `LogLevel.from_string` accepts.
- The clean architecture has **two distinct `LogEntry` / `LogLevel` / `ParseResult` class hierarchies** (`core.models` vs `domain.entities`). Parsers produce one; the application layer type-hints the other. `isinstance` fails across the boundary.
- The `correlate()` public API materializes every log entry in memory (`list(merged)`) despite a misleading `window_size` parameter.
- `RequestIdCorrelation` silently splits groups across its internal buffer boundary, producing duplicate-key groups with partial data.
- Apache/Nginx parsers fail entirely on any line containing escaped quotes inside quoted fields. The detector misclassifies Nginx as `apache_combined`. The Kubernetes container parser is broken for CRI/containerd format (the default since k8s 1.24).
- `Z`-suffix timestamps (Kubernetes, Docker, RFC5424) are parsed as **naive datetimes** (timezone silently stripped), which breaks ordering and crashes correlation against any aware-datetime source.
- Stdin sources have no line-length validation at all — every documented memory bound is bypassed when reading from a pipe.
- The mypy CI step has `continue-on-error: true` and is not in the build job's `needs` list; type errors never block CI. Docker/Kubernetes/Stdin/streaming/correlation/CSV/ReDoS-guard/JSON-depth/GeoIP code paths have no tests.

### Severity tally

| Severity | Count | Theme |
|---|---|---|
| **Critical** | 8 | mmap crashes / unbounded memory; broken normalization recovery; raw `KeyError` on public API; duplicate `LogEntry` class hierarchies; correlate heap TypeError on mixed-tz; parser crash on null nested fields; Apache/Nginx escaped-quote failure |
| **High** | 23 | ReDoS bypass; JSON depth checked post-parse; stdin no length-bound; CRI/Kubernetes misparse; `Z`-suffix timezone strip; format detector mis-routes nginx → apache; correlation buffer splits groups; `correlate()` fully materializes; progress on stdout corrupts JSON pipes; mypy non-blocking in CI; no tests for stream/correlate/stdin/Docker/Kubernetes/correlation-bounds |
| **Medium** | 33 | ReDoS heuristic too weak; CLI `--limit 0/-1`; `--window` accepts negative; CLI exit-code 0 on full failure; BOM/encoding silent corruption; TimestampNormalizer assumes naive=UTC; `psutil` extra unused; `[tool.ruff]`/`[tool.mypy]` missing; docs/code drift; dead handlers; duplicate Protocol definitions |
| **Low** | 19 | Color flag missing; pretty-vs-JSONL undocumented; `correlate` table caps at 50 silently; hostname cache O(n) eviction; `__all__` omissions; `detect` confidence saturates at 1.0; misc style/hygiene |
| **Total** | **83** | After deduplication across six agent reports |

The single highest-leverage repairs are:

1. **Fix the mmap streaming path** (CRIT-1 + CRIT-2 + CRIT-3 + HIGH-S-15). This is the marquee feature and it crashes, is slow, and is unsafe simultaneously.
2. **Unify the duplicate `LogEntry`/`LogLevel`/`ParseResult` hierarchies** (CRIT-4). Until this is fixed every type-related defect compounds.
3. **Make `LogEntry.from_dict` use `LogLevel.from_string`** (CRIT-5). One-line patch, removes a public-API crash.
4. **Fix `NormalizationPipeline.process` `entry.metadata` → `entry.extra`** (CRIT-6). One-line patch, restores resilient-mode operation.
5. **Add stdin line-length validation** (HIGH-S-1). Closes the only side that bypasses every memory bound.
6. **Add the missing test classes for streaming sources, stdin, Docker, Kubernetes, correlation bounds, and CSV sanitization** (HIGH-T-1..4). Several of the critical bugs above would have been caught by the obvious test.

---

## Methodology — Phase 1 plan that was executed

Six parallel review streams, scope-partitioned to avoid duplicated work:

| Stream | Files in scope | Output |
|---|---|---|
| A. Security & Input Validation | `core/security.py`, all parsers, `file_source.py`, `stdin_source.py`, `cli/output.py`, `cli/commands.py`, `correlation/strategies.py` | 11 findings, 8 verified defenses |
| B. Parser Correctness | `parsers/*`, `detection/*`, `core/base.py`, infrastructure adapters | 18 findings, 14 verified behaviors |
| C. Application & Domain Logic | `__init__.py`, `application/*`, `domain/*`, `core/{models,base,exceptions}.py` | 16 findings, 10 verified behaviors |
| D. Infrastructure & Streaming | `infrastructure/sources/*`, `correlation/strategies.py`, `normalization/*`, `infrastructure/adapters/*` | 16 findings, 11 verified behaviors |
| E. CLI & Display | `cli/main.py`, `cli/commands.py`, `cli/output.py`, `__init__.py`, `__main__.py`, `README.md`, `pyproject.toml` | 15 findings, 10 verified behaviors |
| F. Tests, Packaging, CI, Docs | `tests/*`, `pyproject.toml`, `.github/workflows/*`, `LICENSE`, `README.md`, `docs/*` | 18 findings, 12 verified behaviors |

Severity rubric (applied uniformly across all agents):

- **CRITICAL** — Public API crashes on documented input; data corruption; advertised guarantee bypassed; clean-architecture invariant violated; trivially-triggered DoS or memory exhaustion.
- **HIGH** — Documented feature missing or broken; defense-in-depth bypassed via a non-obvious path; major test/CI gap on advertised functionality; user-visibly wrong output on common input.
- **MEDIUM** — Edge-case crash or wrong output; missing hardening; weak heuristic; doc/code drift; resource leak under uncommon condition.
- **LOW** — Cosmetic, hygiene, missing flag, minor performance, easily-corrected style.

Each finding below cites `file:line` and includes evidence, impact, and remediation. Findings labeled (e.g.) `[SEC-3]` use the stream prefix S=Security, P=Parser, A=Application, I=Infrastructure, C=CLI, T=Tests/CI/Docs. Cross-stream duplicates have been merged with both witnesses cited.

---

## CRITICAL findings

### [CRIT-1] mmap streaming crashes with unguarded `ValueError` on empty or rotated files
- **File:** `src/ulp/infrastructure/sources/file_source.py:173-216`
- **Witnesses:** Stream D
- **Evidence:** `with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:` — Python's `mmap.mmap` raises `ValueError: cannot mmap an empty file` on size-0 files. `_use_mmap` is decided once in `__init__` from `stat().st_size`; if a file is >100 MB at construction time and is then rotated (truncated to 0) before `read_lines()` is consumed, the mmap path runs and crashes with an unhandled exception.
- **Impact:** Log rotation is a routine production event. Any >100 MB file rotated between source construction and the first `next(read_lines)` causes a process-level crash with no recovery path.
- **Remediation:** Guard inside `_read_lines_mmap`: `if self.path.stat().st_size == 0: return` (or wrap `mmap.mmap(...)` in `try/except ValueError` and fall through to `_read_lines_regular`).

### [CRIT-2] mmap path uses per-byte Python loop — O(n) at Python speed defeats mmap and makes the marquee feature unusable
- **File:** `src/ulp/infrastructure/sources/file_source.py:188-203`
- **Witnesses:** Stream D (benchmarked: ~0.265 ms per 8192-byte chunk → ~347 s loop overhead for a 10 GB file *before* any decode/parse); Stream C (independently flagged as MEDIUM)
- **Evidence:**
  ```python
  for byte in chunk:                          # Python-level iteration
      if byte == ord("\n"):
          ...
      else:
          buffer.append(byte)
  ```
- **Impact:** The advertised "memory-efficient streaming for 1–10 GB files" is functionally slower than the regular file iterator (which runs in C). The mmap path actively harms the workload it was designed to optimize.
- **Remediation:** Replace the loop with `mm.find(b"\n", position)` to locate newlines, then slice `mm[start:nl]`. All scanning stays in C.

### [CRIT-3] mmap buffer accumulates without bound — `MAX_LINE_LENGTH` bypassed entirely; one no-newline 10 GB file → 10 GB RAM
- **File:** `src/ulp/infrastructure/sources/file_source.py:180-216`
- **Witnesses:** Stream S (HIGH), Stream D (CRITICAL); merged to CRITICAL on the stronger evidence
- **Evidence:** `validate_line_length` is only called when a `\n` byte is encountered (line 196). The intervening accumulation into `buffer = bytearray()` has no size guard. A 10 GB file with zero newlines accumulates 10 GB in Python heap before any check runs.
- **Impact:** The documented 10 MB line cap is defeated for the mmap path. A single crafted or naturally-occurring no-newline file causes OOM kill, undermining the documented security model entirely.
- **Remediation:** Check `len(buffer) > MAX_LINE_LENGTH` inside the accumulation loop (or after each chunk) and raise `LineTooLongError` before the file is fully read.

### [CRIT-4] Two distinct `LogEntry` / `LogLevel` / `ParseResult` class hierarchies coexist; `isinstance` fails across the layer boundary
- **File:** `src/ulp/core/models.py` vs `src/ulp/domain/entities.py`
- **Witnesses:** Stream A
- **Evidence:**
  ```python
  from ulp.core.models import LogEntry as CoreLogEntry
  from ulp.domain.entities import LogEntry as DomainLogEntry
  isinstance(CoreLogEntry(), DomainLogEntry)  # False
  ```
  All parsers (`parsers/*.py`) import and produce `core.models.LogEntry`. The application layer (`application/parse_logs.py`, `application/correlate_logs.py`, `application/ports.py`) type-hints `domain.entities.LogEntry`. The public `__init__.py` re-exports the `core.models` version. `LogLevel.from_string` mappings also diverge: `domain.entities` includes `"information"→INFO` and `"panic"→EMERGENCY`; `core.models` does not.
- **Impact:** Type-checking is meaningless across the layer boundary. Plugins or external code that pattern-match on type identity break in ways that are hard to debug. Silent semantic drift in `LogLevel.from_string` depending on import path.
- **Remediation:** Delete one hierarchy. The path of least disruption is to remove `core/models.py` and have all modules import from `domain.entities` (true clean-architecture direction); `BaseParser` then either moves to `domain/` or stays as a thin adapter. Update the public `__init__.py` re-exports accordingly.

### [CRIT-5] `LogEntry.from_dict` raises raw `KeyError` for any unfamiliar level name — escapes the `ULPError` hierarchy
- **File:** `src/ulp/core/models.py:275` (and the equivalent at `src/ulp/domain/entities.py:296`)
- **Witnesses:** Stream A
- **Evidence:**
  ```python
  entry.level = LogLevel[data.get("level", "UNKNOWN")]   # KeyError on "WARN", "PANIC", "fatal", any lowercase, etc.
  ```
  This is asymmetric with `LogLevel.from_string`, which the same module defines specifically to fall back to `UNKNOWN`. Verified: `LogEntry.from_dict({"level": "WARN"})` raises `KeyError('WARN')`.
- **Impact:** The public deserializer crashes on inputs produced by other tools (or by the library's own non-canonical level names) with an exception that callers can't catch as a `ULPError`.
- **Remediation:** Replace with `entry.level = LogLevel.from_string(data.get("level", "UNKNOWN"))`. One-line patch.

### [CRIT-6] `NormalizationPipeline` error-recovery path crashes with `AttributeError` — `stop_on_error=False` is broken
- **File:** `src/ulp/infrastructure/normalization/pipeline.py:80`
- **Witnesses:** Stream A
- **Evidence:**
  ```python
  except Exception as e:
      self._error_count += 1
      if self.stop_on_error:
          raise
      entry.metadata["normalization_error"] = str(e)   # LogEntry has no .metadata attribute
      yield entry
  ```
  `LogEntry` has `extra` and `parse_errors`, but not `metadata`. The resilient path is the default mode and itself raises `AttributeError`.
- **Impact:** Every normalization-step exception causes a second exception in the handler that obscures the first; resilient mode does not exist in practice.
- **Remediation:** `entry.extra["normalization_error"] = str(e)` (or append to `entry.parse_errors`). One-line patch.

### [CRIT-7] `correlate()` heap-merge crashes with `TypeError` on mixed naive/aware datetimes
- **File:** `src/ulp/application/correlate_logs.py:147`, `src/ulp/domain/entities.py` (`CorrelationGroup.__post_init__`)
- **Witnesses:** Stream A
- **Evidence:** `heapq.heappush(heap, (ts, source_id, entry, source))` compares tuples by their first element; if one source produced aware timestamps and another produced naive (very common with mixed-format logs — see [CRIT-8] / [HIGH-P-3] which makes most Z-suffix timestamps naive), Python raises `TypeError: can't compare offset-naive and offset-aware datetimes`. The exception is unhandled and not a `ULPError`.
- **Impact:** `ulp correlate app.log nginx.log` crashes for any realistic combination of sources. The correlation feature is unsafe to use across heterogeneous logs.
- **Remediation:** Normalize timestamps to UTC at heap-insertion: `ts = entry.timestamp if (entry.timestamp and entry.timestamp.tzinfo) else (entry.timestamp.replace(tzinfo=timezone.utc) if entry.timestamp else datetime.min.replace(tzinfo=timezone.utc))`. Apply the same in `CorrelationGroup.__post_init__` and `timeline()`. Pair this with [CRIT-8].

### [CRIT-8] `KubernetesAuditParser` crashes with `AttributeError` on `responseStatus: null`
- **File:** `src/ulp/parsers/kubernetes.py:336`
- **Witnesses:** Stream B
- **Evidence:**
  ```python
  response_code = data.get("responseStatus", {}).get("code", 200)
  ```
  When `responseStatus` is present in the JSON but its value is `null` (a normal occurrence in Kubernetes audit events at the `RequestReceived` stage), `data.get("responseStatus", {})` returns `None`, and `None.get(...)` raises. `parse_line` is documented to never raise; this violation breaks `parse_stream` iteration.
- **Impact:** Any audit log containing a `RequestReceived` event crashes the parser, terminating the iterator and ending the parse.
- **Remediation:** `response_status = data.get("responseStatus") or {}` then `response_code = response_status.get("code", 200)`.

### [CRIT-9] Apache combined / Nginx parsers fail entirely on any line containing an escaped quote in a quoted field
- **File:** `src/ulp/parsers/apache.py:176-181`, `src/ulp/parsers/nginx.py:29-38`
- **Witnesses:** Stream B
- **Evidence:** Both regexes use `[^"]*` for request, referer, user-agent. A real log line `... "GET /search?q=\"test\" HTTP/1.1" 200 1234 "-" "-"` does not match; the entry returns `parse_errors=['Line does not match ...']` and `level=UNKNOWN`.
- **Impact:** Real-world access logs from clients that include unescaped or escaped quotes in URLs/UA strings (curl, wget, search bots) silently drop. This is one of the two most-deployed log formats on the internet.
- **Remediation:** Replace `[^"]*` with `(?:[^"\\]|\\.)*` for each quoted-field capture. Apply to request, referer, user-agent in both parsers.

---

## HIGH findings

### [HIGH-S-1] Stdin sources have no line-length validation — every memory bound bypassed via pipes
- **File:** `src/ulp/infrastructure/sources/stdin_source.py:44-55, 135-151`
- **Witnesses:** Stream S, Stream D (both flagged independently)
- **Evidence:** `StdinStreamSource.read_lines` and `BufferedStdinSource.read_lines` (both buffer-replay and live-read branches) yield `line.rstrip("\n\r")` with no call to `validate_line_length`. Every file source calls it; only stdin is uniformly missing.
- **Impact:** `cat huge.bin | ulp parse` with a single multi-gigabyte line bypasses `MAX_LINE_LENGTH` entirely. The only documented memory guarantee is invalid for piped input.
- **Remediation:** Add `validate_line_length(stripped)` in both `read_lines` paths in `stdin_source.py`.

### [HIGH-S-2] ReDoS heuristic in `validate_regex_pattern` misses every classic catastrophic-backtracking pattern; user `--grep` is unbounded
- **File:** `src/ulp/core/security.py:179-197`, `src/ulp/cli/commands.py:152-159`
- **Witnesses:** Stream S
- **Evidence:** `validate_regex_pattern` only checks four hand-written dangerous patterns. Each of `(a|a)+`, `(\w+\s?)+`, `(x+)+$`, `([a-zA-Z]+)*` compiles and passes. The CLI routes user `--grep` straight to `pattern.search(e.message)` per entry. `REGEX_TIMEOUT_SECONDS = 5.0` is set in `security.py` but never wired into any matching call.
- **Impact:** A single `--grep '(\w+\s?)+'` against a log file with `aaaaaaaaaaaa!` lines hangs the process at 100% CPU. Bounded denial-of-service via the most-used CLI option.
- **Remediation:** Either (a) use the `regex` PyPI library which has a `timeout=` argument, (b) actually enforce `REGEX_TIMEOUT_SECONDS` by running matches in a `concurrent.futures.ThreadPoolExecutor` with timeout, or (c) replace the heuristic list with a real static analyzer (e.g., `safe-regex` logic).

### [HIGH-S-3] `validate_json_depth` runs *after* `json.loads` — depth attack hits the unguarded recursive C parser first
- **File:** `src/ulp/parsers/json_parser.py:49, 64`
- **Witnesses:** Stream S
- **Evidence:** Line 49 invokes `json.loads(line.strip())` first; line 64 invokes `validate_json_depth(data)` second. CPython's `json.loads` is recursive in C — a 10 MB line with deep bracket nesting (well under `MAX_LINE_LENGTH`) blows the C stack before the validator can run.
- **Impact:** A single malicious JSON log line crashes the process. The defense is ordered backwards.
- **Remediation:** Pre-scan the raw string for maximum bracket nesting (O(n) character scan) before `json.loads`; raise `SecurityValidationError` if it exceeds `MAX_JSON_DEPTH`.

### [HIGH-S-4] Docker and Kubernetes parsers call `json.loads` with no depth check at all
- **File:** `src/ulp/parsers/docker.py:40, 95`; `src/ulp/parsers/kubernetes.py:110, 215, 299, 374, 475, 526`
- **Witnesses:** Stream S
- **Evidence:** Eight `json.loads` call sites across these two modules do not import or invoke `validate_json_depth`. Several occur inside `can_parse` (i.e., during detection on sample lines from arbitrary files).
- **Impact:** The depth guard that exists for `JSONParser` is a single defense in eight unguarded sites. Any Docker/Kubernetes-formatted line with deep nesting crashes the process.
- **Remediation:** Apply the pre-parse depth scan from [HIGH-S-3] uniformly to all `json.loads` call sites. Centralize via a helper `safe_json_loads`.

### [HIGH-P-1] `BaseParser._parse_timestamp` silently strips `Z` UTC suffix, producing naive datetimes
- **File:** `src/ulp/core/base.py:128-138`
- **Witnesses:** Stream B
- **Evidence:** `TIMESTAMP_FORMATS` includes literal-Z formats (`"%Y-%m-%dT%H:%M:%S.%fZ"`, `"%Y-%m-%dT%H:%M:%SZ"`). `datetime.strptime` does not set `tzinfo` when matching a literal character. Result: `datetime(2024,1,15,10,30,0)` with `tzinfo=None`. RFC5424, Kubernetes, and Docker RFC3339Nano logs all route through this code.
- **Impact:** Timestamps that explicitly state UTC are stored as naive local time. Sort order across mixed sources is wrong. Combined with [CRIT-7], `correlate()` raises `TypeError` whenever a Z-suffix source meets an offset-aware source.
- **Remediation:** Replace the literal-Z formats with `"%Y-%m-%dT%H:%M:%S.%f%z"` and `"%Y-%m-%dT%H:%M:%S%z"`. In Python 3.11+ these accept `Z` directly. For 3.10 compatibility, pre-substitute `Z` → `+00:00`.

### [HIGH-P-2] `apache_combined` magic pattern wins over `nginx_access` even on pure Nginx lines
- **File:** `src/ulp/detection/signatures.py:29-38, 56-68`
- **Witnesses:** Stream B
- **Evidence:** `apache_combined`'s magic regex matches any CLF-style line (Apache *or* Nginx); its weight is `1.3` vs nginx's `1.2`. Verified: a pure nginx line `192.168.1.1 - - [27/Jan/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla"` detects as `apache_combined` with confidence `1.0`.
- **Impact:** Every nginx access log reports `format_detected="apache_combined"`. Users filtering by format see wrong attribution. (The parser itself is the right one in practice since both share most fields, but the report is misleading and tooling that branches on format breaks.)
- **Remediation:** Raise `nginx_access` weight (e.g., to `1.35`) or add a discriminating pattern (e.g., `$body_bytes_sent` style features) to break the tie deterministically toward Nginx.

### [HIGH-P-3] `KubernetesContainerParser` misparses CRI-O / containerd lines (default since k8s 1.24)
- **File:** `src/ulp/parsers/kubernetes.py:43-45`
- **Witnesses:** Stream B
- **Evidence:** The regex `^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(.*)$` (a) requires sub-second precision (lines like `2024-01-15T10:30:00Z stdout F msg` don't match), and (b) captures the stream type / partial flag (`stdout F`) into the message field.
- **Impact:** Every Kubernetes node running containerd (the default runtime since 1.24) produces logs that come out with `message="stdout F <real message>"` or fail to parse at all.
- **Remediation:** `^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(?:(?:stdout|stderr)\s+[FP]\s+)?(.*)$`.

### [HIGH-P-4] `ApacheCombinedParser.can_parse` returns up to `1.1`, violating the documented `0.0–1.0` contract
- **File:** `src/ulp/parsers/apache.py:247`
- **Witnesses:** Stream B
- **Evidence:** `return (combined_matches / len(sample)) * 1.1`. For a fully-matching sample the score is `1.1`. The value propagates unchanged through the registry and into `LogEntry.parser_confidence`.
- **Impact:** Any downstream gate on `confidence == 1.0` or `confidence <= 1.0` breaks. The `BaseParser.can_parse` docstring explicitly documents the range.
- **Remediation:** `return min(1.0, (combined_matches / len(sample)) * 1.1)`.

### [HIGH-P-5] `SyslogRFC3164Parser` assigns current year without rollover — December logs read in May are dated to next year
- **File:** `src/ulp/parsers/syslog.py:122-134`
- **Witnesses:** Stream B
- **Evidence:** `current_year = datetime.now().year; ts_with_year = f"{ts} {current_year}"`. A `Dec 25 00:00:00 ...` line read in May 2026 gets year 2026 instead of 2025. `KubernetesComponentParser._parse_klog` (lines 195–197) implements correct rollover logic that has not been applied here.
- **Impact:** Logs from the previous calendar year are dated as if from the future. Time-range queries silently miss entries; correlation breaks.
- **Remediation:** Mirror `KubernetesComponentParser`'s rollover: if `parsed_month > datetime.now().month + 1`, subtract one year.

### [HIGH-P-6] `GenericParser` 10-digit timestamp pattern consumes the prefix of millisecond timestamps
- **File:** `src/ulp/parsers/generic.py:40-43`
- **Witnesses:** Stream B
- **Evidence:** Patterns are checked in order; the 10-digit pattern `r'^(\d{10})\s*'` matches the first 10 digits of a 13-digit timestamp, leaving `000 ` to leak into the message.
- **Impact:** Logs from Java/Node.js (millisecond Unix timestamps) get `message="000 <real message>"`.
- **Remediation:** Swap order (13-digit first), or use a non-digit boundary: `r'^(\d{10})(?!\d)\s*'`.

### [HIGH-A-1] `RequestIdCorrelation` splits groups across the buffer boundary — duplicate `correlation_key` groups with partial data
- **File:** `src/ulp/infrastructure/correlation/strategies.py:93-98`
- **Witnesses:** Stream A, Stream D (independently flagged)
- **Evidence:** When `count > buffer_size`, `yield from self._emit_groups(id_groups); id_groups = defaultdict(list)`. Verified: 15 entries with `request_id="req-1"` and `buffer_size=10` produce two groups both keyed `"req-1"` (sizes 10 and 5).
- **Impact:** `result.groups` contains the same key multiple times; consumers building request timelines miss cross-boundary log relationships and may double-count.
- **Remediation:** Either (a) accumulate keys seen so far so a re-flushed key continues into the existing group, or (b) document that `buffer_size` must exceed total unique entries-per-key, or (c) maintain a key-emission set and emit only when a key has been "stable" for N lines.

### [HIGH-A-2] `correlate()` materializes all entries via `list(merged)` — `window_size` parameter is misleading
- **File:** `src/ulp/application/correlate_logs.py:79`; `src/ulp/__init__.py:285`
- **Witnesses:** Stream A
- **Evidence:** `all_entries = list(merged)` followed by a code comment "For very large datasets, implement windowed correlation" — the streaming path is an acknowledged stub. The public `correlate()` accepts `window_seconds` but passes a hardcoded `window_size=10000` to the use case, which is only used inside individual strategies (and only causes the [HIGH-A-1] bug).
- **Impact:** `correlate()` on 10 GB of logs (or even 1 GB) loads everything into RAM. The "streaming correlation" claim is false for the public API.
- **Remediation:** Either implement the windowed merge path or remove the misleading parameter and document the memory requirement.

### [HIGH-A-3] `print()` patterns proliferate in non-CLI library code (all currently in docstrings, but the pattern is fragile)
- **File:** `pipeline.py:31`, `file_source.py:29,240`, `strategies.py:37,184,308`, `correlate_logs.py:40`, `parse_logs.py:33`
- **Witnesses:** Stream A
- **Evidence:** All current occurrences are inside docstring example blocks (so they do not execute), but the prevalence creates copy-paste risk and any future doctest enablement would emit them to stdout.
- **Impact:** Latent — library currently does not pollute stdout. If a developer ever turns on doctests or copies an example into real code, log output corrupts piped consumers.
- **Remediation:** Move long examples out of docstrings into `docs/`, or wrap them in raw-string markers / use `>>>` doctest format so they're parseable rather than runnable text.

### [HIGH-A-4] Public API inconsistency: `parse()` returns `list[LogEntry]`, `correlate()` returns a result object, `stream_parse()` returns a generator
- **File:** `src/ulp/__init__.py:140-173, 226-288`
- **Witnesses:** Stream A
- **Evidence:** `parse_file` (and its `parse` alias) discards format confidence, error count, and source file metadata. `ParseResult` exists in the codebase but no public function returns it.
- **Impact:** Users cannot inspect detection confidence or error count without dropping to use cases directly. Migrating from `parse()` to that API is a breaking change.
- **Remediation:** Change `parse_file` to return `ParseResult`; keep `result.entries` as the list to minimize disruption. Document `parse()` (the alias) as deprecated in favor of `parse_file`.

### [HIGH-I-1] `HostnameEnricher._resolve` calls `socket.setdefaulttimeout` — process-global mutation that degrades every other socket op
- **File:** `src/ulp/infrastructure/normalization/steps.py:278`
- **Witnesses:** Stream D
- **Evidence:** `socket.setdefaulttimeout(self.timeout)` permanently sets a process-wide default; never restored. Other threads/coroutines doing HTTP / DB I/O inherit the 0.5 s timeout.
- **Impact:** Embedding ULP in a multi-threaded application (web server, ETL worker) silently degrades unrelated network operations.
- **Remediation:** Use a per-call timeout via `socket.create_connection((ip, 0), timeout=self.timeout)` or `signal.alarm` (POSIX). Never touch `setdefaulttimeout` in library code.

### [HIGH-I-2] `GeoIPEnricher` MaxMind reader is only closed via unreliable `__del__`
- **File:** `src/ulp/infrastructure/normalization/steps.py:394-400`
- **Witnesses:** Stream D
- **Evidence:** `__del__` is the only close path; no `close()` method, no context-manager methods. CPython skips `__del__` during interpreter shutdown and on reference cycles.
- **Impact:** File-descriptor leak on long-running daemons processing many files; clean shutdown is not guaranteed.
- **Remediation:** Add `__enter__`/`__exit__` and an explicit `close()`. Document the `with` requirement.

### [HIGH-C-1] CLI `parse` / `stream` reject `-` as a filename → documented stdin pipelining is broken
- **File:** `src/ulp/cli/main.py:48, 121, 232`
- **Witnesses:** Stream C
- **Evidence:** `type=click.Path(exists=True)` rejects `-`. Verified: `echo test | python -m ulp parse -- -` exits 2 with `Path '-' does not exist`. `ulp stream` has no stdin path at all.
- **Impact:** Users following the README's piping pattern get a usage error. Composability with standard Unix pipes is broken.
- **Remediation:** Use `type=click.Path(exists=True, allow_dash=True)` for `parse`. Add a `-` short-circuit in `stream_command` that constructs a `BufferedStdinSource`.

### [HIGH-C-2] `--level` choices exclude TRACE, NOTICE, ALERT, EMERGENCY — syslog filtering is incomplete
- **File:** `src/ulp/cli/main.py:61`
- **Witnesses:** Stream C
- **Evidence:** `type=click.Choice(["debug", "info", "warning", "error", "critical"])` — but `LogLevel` defines TRACE, NOTICE, ALERT, EMERGENCY (used by RFC 3164/5424 logs).
- **Impact:** Users of syslog-sourced logs cannot filter to NOTICE/ALERT/EMERGENCY at the CLI. `--level error` silently includes ALERT/EMERGENCY (because they sort higher), which may or may not be intuitive.
- **Remediation:** Expand the Choice to all `LogLevel.from_string`-accepted values: `["trace","debug","info","notice","warning","error","critical","alert","emergency"]`.

### [HIGH-C-3] `stream` command prints progress + summary to stdout — corrupts piped JSON consumers
- **File:** `src/ulp/cli/commands.py:326-361`
- **Witnesses:** Stream C
- **Evidence:** `console.print(...)` writes to stdout (the default `Console()` instance). `--progress` defaults to True. With `--output json`, every progress line is flushed to stdout between JSONL entries → invalid JSON. The summary line `Processed N entries` similarly lands on stdout.
- **Impact:** `ulp stream --format syslog huge.log | jq '.'` fails. The default mode is broken for the documented use case.
- **Remediation:** Route progress and the summary through `error_console` (stderr), per standard Unix convention.

### [HIGH-T-1] No tests for `stream` or `correlate` CLI commands
- **File:** `tests/test_cli.py`
- **Witnesses:** Stream F
- **Evidence:** Only `TestParseCommand` and `TestDetectCommand` exist. `stream` and `correlate` are top-level documented commands.
- **Impact:** Regressions in the most complex CLI paths go undetected. Many CRITICAL/HIGH findings above would have surfaced as test failures had these tests existed.
- **Remediation:** Add `TestStreamCommand`, `TestCorrelateCommand` using `CliRunner` with `tmp_path` fixtures.

### [HIGH-T-2] `LargeFileStreamSource` mmap path is never actually exercised by tests
- **File:** `tests/test_infrastructure.py:76`
- **Witnesses:** Stream F
- **Evidence:** The existing test asserts `source._use_mmap is False` (small file). No test exercises the mmap branch. CRIT-1, CRIT-2, CRIT-3 all live in code that has zero direct test coverage.
- **Impact:** The marquee feature has no test signal at all.
- **Remediation:** Use `monkeypatch` to lower the mmap threshold to 1 byte, run a real file through, assert `_use_mmap is True` and that output matches reference parsing.

### [HIGH-T-3] No tests for `StdinStreamSource` / `BufferedStdinSource`
- **File:** `tests/test_infrastructure.py`, `tests/test_cli.py`
- **Witnesses:** Stream F
- **Evidence:** Both classes are public exports but no test exercises `read_lines()` or `peek()`. `test_parse_no_files` checks CLI output strings, not the source itself.
- **Impact:** The stdin path (which [HIGH-S-1] shows is the most unguarded path) has no signal.
- **Remediation:** `monkeypatch sys.stdin = io.StringIO("line1\nline2\n")`; call `source.read_lines()` directly; assert behavior on empty, single-line, multi-line, and over-`MAX_LINE_LENGTH` cases.

### [HIGH-T-4] Docker JSON and Kubernetes parsers have zero test coverage
- **File:** `tests/test_parsers.py`
- **Witnesses:** Stream F
- **Evidence:** No `TestDocker*` or `TestKubernetes*` class. Both parsers are registered, documented, and broken (see [CRIT-8] and [HIGH-P-3]).
- **Impact:** Documented formats with broken implementations and no test signal.
- **Remediation:** Mirror the structure of `TestNginxAccessParser` and `TestSyslogRFC5424Parser` for each.

### [HIGH-T-5] `MAX_ORPHAN_ENTRIES` and `MAX_SESSION_GROUPS` bounds are never tested
- **File:** `tests/test_security.py:11-12`
- **Witnesses:** Stream F
- **Evidence:** Both constants are imported but never asserted against. The bound code in `strategies.py` is well-implemented (see Verified defenses) but a regression would not be caught.
- **Impact:** Defense-in-depth has no regression signal.
- **Remediation:** Feed > `MAX_ORPHAN_ENTRIES` un-correlated entries through `RequestIdCorrelation`; assert orphan list is capped and warning is emitted. Same for `SessionCorrelation`.

### [HIGH-T-6] `LogEntry.from_dict` round-trip does not cover HTTP / network / correlation sub-models
- **File:** `tests/test_models.py:213`
- **Witnesses:** Stream F
- **Evidence:** Round-trip test only populates `source.file_path`. None of HTTP, network, correlation are exercised.
- **Impact:** Combined with [CRIT-5] (raw KeyError), serialization/deserialization is essentially untested.
- **Remediation:** Build a fully-populated `LogEntry`, round-trip via `to_dict` → `from_dict`, assert deep equality on all sub-models.

---

## MEDIUM findings

### Security
- **[MED-S-1]** `validate_regex_pattern` hardcodes `re.IGNORECASE` (`core/security.py:197`). Silently alters user grep semantics; `--grep 'Error'` matches `error`/`ERROR`. **Fix:** Expose `--ignore-case` / `-i`; default case-sensitive.
- **[MED-S-2]** `check_symlink` only warns; doesn't block (`core/security.py:225-247`, `file_source.py:56-58`). TOCTOU between `is_symlink` and `resolve`. Warnings can be suppressed via `PYTHONWARNINGS=ignore`. **Fix:** Add `block_symlinks: bool = True` parameter that raises `SecurityValidationError`.
- **[MED-S-3]** `re.compile` called per log line in `SyslogRFC5424Parser._parse_structured_data` (`syslog.py:248,259`) and `DockerDaemonParser._parse_extra_fields` (`docker.py:217`). Python's pattern cache mitigates but doesn't eliminate the overhead at 10 GB scale. **Fix:** Hoist to class-level constants.
- **[MED-S-4]** `validate_json_depth` recurses Python-style over every leaf (`security.py:119-148`). Doubles CPU for large flat objects; no security benefit for breadth. **Fix:** Replace with O(depth) early-exit or pre-parse bracket scan.
- **[MED-S-5]** `MAX_ORPHAN_ENTRIES` bound enforcement is correct in `RequestIdCorrelation`, but [HIGH-A-1] (buffer split) and [HIGH-A-2] (full materialization) limit its protective value in practice.

### Parser
- **[MED-P-1]** RFC5424 structured-data param parser doesn't handle `\"` escapes (`syslog.py:259`). Values truncate at first internal quote. **Fix:** `(\S+)="((?:[^"\\]|\\.)*)"` and unescape.
- **[MED-P-2]** RFC5424 SD field regex `.*?` stops at first `]` (`syslog.py:152,248`). Values containing `]` truncate. **Fix:** Use a quote-aware pattern or state machine.
- **[MED-P-3]** `DockerDaemonParser` msg field truncates at first internal `"` (`docker.py:123`). **Fix:** `msg="((?:[^"\\]|\\.)*)"`.
- **[MED-P-4]** Python logging parser misses `WARN` and `NOTSET` (`python_logging.py:29-63`). **Fix:** Expand alternation, route through `LogLevel.from_string`.
- **[MED-P-5]** `_parse_request` splits on whitespace (`apache.py:117-140`, `nginx.py:117-142`). URLs with unencoded spaces produce `version="with"` etc. **Fix:** Detect `HTTP/X.Y` as last token.
- **[MED-P-6]** `SyslogRFC3164Parser.PATTERN_ALT` matches non-syslog content (`syslog.py:51-57`). Inflates detection confidence; misassigns `hostname`. **Fix:** Require a tag-like token in the fallback, or count only `PATTERN` in `can_parse`.

### Application / Domain
- **[MED-A-1]** `ParseResult.__post_init__` cannot distinguish pre-set `entry_count=0` from "not set" (`core/models.py:310-314`, `domain/entities.py:436-440`). Streaming sentinel values are clobbered. **Fix:** Use `int | None` with `None` sentinel.
- **[MED-A-2]** `LogLevel.from_string` "f" maps to CRITICAL (`core/models.py:79`, `domain/entities.py:84`). Java JUL "F" = FINE (≈DEBUG), so JUL parsing inverts severity. **Fix:** Remove or document; map "f" → UNKNOWN.
- **[MED-A-3]** `LogSourcePort` Protocol duplicated in `domain/services.py:157` and `application/ports.py:20`. Dead code in domain; only application version is used. **Fix:** Delete the domain copy.
- **[MED-A-4]** Dead `UnicodeDecodeError` handler in `_read_lines_mmap` (`file_source.py:192-199`). `errors="replace"` never raises. Under `errors="strict"`, lines silently disappear with no counter. Also independently flagged by Stream D as MED-I-3. **Fix:** Remove the dead path or handle strict mode with explicit counting.
- **[MED-A-5]** `LargeFileStreamSource._read_lines_mmap` byte-loop performance (covered as CRIT-2).

### Infrastructure
- **[MED-I-1]** BOM silently corrupts first log line (`file_source.py:70-80`). Default encoding `"utf-8"` not `"utf-8-sig"`. Windows-exported logs (Notepad, PowerShell `Out-File`) start with `﻿`. **Fix:** Default to `utf-8-sig`.
- **[MED-I-2]** `errors="replace"` default silently corrupts; replacement-char expansion can also cause false `LineTooLongError` near the size cap (`file_source.py:36`, `stdin_source.py:30`, `core/security.py:113`). **Fix:** Document; consider `strict` default with explicit `--lenient-encoding`.
- **[MED-I-3]** `TimestampNormalizer` assumes naive datetimes are UTC (`normalization/steps.py:63-65`). Most syslog/Apache/Nginx logs are server local-time. **Fix:** Constructor parameter `naive_tz` (no default; force user choice).
- **[MED-I-4]** `SessionCorrelation` silently drops entries with no session key (`strategies.py:363-365`). No orphan tracking, no warning. **Fix:** Mirror `RequestIdCorrelation`'s orphan pattern.
- **[MED-I-5]** `ChunkedFileStreamSource` final progress callback fires with `total_bytes=0` on empty files (`file_source.py:315-316`). Crashes naive `pct = bytes_read / total_bytes` callers. **Fix:** Guard `if self._file_size > 0`.

### CLI / Display
- **[MED-C-1]** `--limit 0` silently means "no limit"; `--limit -1` drops last entry (`commands.py:161`). **Fix:** `click.IntRange(min=1)`; check `if limit is not None`.
- **[MED-C-2]** `--window` accepts negative values (`main.py:133`). Produces empty results with no error. **Fix:** `click.FloatRange(min=0.0, min_open=True)`.
- **[MED-C-3]** `parse` returns exit code 0 when all files fail (`commands.py:140-145`). CI pipelines can't gate on it. **Fix:** Track `had_error`; return 1 if any failure.
- **[MED-C-4]** `detect` returns 0 on IOError (`main.py:285-286`). **Fix:** Track and `ctx.exit(1)` after the loop.
- **[MED-C-5]** `detect` and `formats` ignore `--quiet` and bypass `ctx.obj["console"]` (`main.py:257-325`). **Fix:** Read both from `ctx.obj`.
- **[MED-C-6]** `stream` command has no `--quiet` pass-through (`main.py:198-228`, `commands.py:304-311`). Inconsistent with other commands.
- **[MED-C-7]** JSON output differs: `parse --output json` → single array, `stream --output json` → JSONL. Undocumented; `jq` queries don't port. **Fix:** Document; consider `--jsonl` flag on `parse`.

### Tests / CI / Docs
- **[MED-T-1]** `mypy` step has `continue-on-error: true` and `typecheck` not in `build`'s `needs` (`.github/workflows/ci.yml:85`). Type errors never block CI. **Fix:** Remove `continue-on-error` once baseline passes; add to `needs`.
- **[MED-T-2]** `psutil` "benchmark" extra has no source usage (`pyproject.toml:60-62`). **Fix:** Either implement memory reporting or remove the extra.
- **[MED-T-3]** No `[tool.ruff]` / `[tool.mypy]` config (`pyproject.toml`). CI runs `ruff check src/` and `mypy src/ulp` with implicit defaults. **Fix:** Add explicit config blocks.
- **[MED-T-4]** `CHANGELOG.md` referenced in `pyproject.toml:78` but does not exist. Dead PyPI link. **Fix:** Create or remove.
- **[MED-T-5]** Docs reference two non-existent files (`docs/ARCHITECTURE-29JAN2026.md:821-822`, `docs/README-29JAN2026.md:86,92`): `DESIGN-PRINCIPLES-29JAN2026.md`, `EXTENSIONS-29JAN2026.md`. **Fix:** Create or update links.
- **[MED-T-6]** All doc files carry `-29JAN2026` suffix; duplicates exist in repo root. No tooling maintains them. **Fix:** Rename to standard names; rely on git history for dating.
- **[MED-T-7]** `GeoIPEnricher` exported but has no tests (`infrastructure/__init__.py:26`). [HIGH-I-2] resource-leak bug is in the same untested class.
- **[MED-T-8]** No pip caching in CI (`.github/workflows/ci.yml`). Each Python-version × matrix run cold-installs. **Fix:** `cache: pip` on `actions/setup-python`.

---

## LOW findings

### Security / Hygiene
- **[LOW-S-1]** `ULPError.__str__` includes `details` which may include the first 100 bytes of a parse-failing log line (`core/exceptions.py:21-23,39`). Could leak secrets to stderr/log aggregators. **Fix:** Redact in default `__str__`; expose under `--verbose`.
- **[LOW-S-2]** `check_symlink` has a TOCTOU window between `is_symlink()` and `resolve()` (`security.py:236-247`). **Fix:** Use `os.open` with `O_NOFOLLOW`.

### Parser
- **[LOW-P-1]** Detector `confidence` saturates at 1.0 even for very partial matches (`detector.py:109`). The normalization `min(1.0, score/max(max_score, 1.0))` produces 1.0 whenever the winner's raw score ≥ 1.0. **Fix:** Use a denominator tied to expected ideal score (e.g., `sig.weight * 4`).
- **[LOW-P-2]** `KubernetesContainerParser.can_parse` computes `json_logs` but doesn't include it in the returned score (`kubernetes.py:108-114`). JSON-formatted k8s container logs always get 0.3. **Fix:** Include the term.
- **[LOW-P-3]** `LogLevel` `"f"` → CRITICAL flagged as fragile when used outside explicit-level fields (covered as MED-A-2).

### Application
- **[LOW-A-1]** `correlate()` `LogLevel.from_string` "information" / "panic" only on `domain.entities` side, not on `core.models` (covered under CRIT-4).
- **[LOW-A-2]** `window_size=10000` hardcoded in public `correlate()` call (`__init__.py:285`). Not exposed, not documented. Tied to [HIGH-A-1] / [HIGH-A-2].

### Infrastructure
- **[LOW-I-1]** `file_source.__all__` omits `ChunkedFileStreamSource` (`file_source.py:16`). Wildcard imports drop it.
- **[LOW-I-2]** `LevelNormalizer` only activates on `LogLevel.UNKNOWN` (`steps.py:122-123`). Mis-set levels are not corrected. **Fix:** Document or add `force_normalize`.
- **[LOW-I-3]** `HostnameEnricher` cache eviction is O(n) (`steps.py:284-288`); halves cache repeatedly under near-overflow working sets. **Fix:** `OrderedDict.popitem(last=False)`.

### CLI / Display
- **[LOW-C-1]** Progress uses `\r` inside Rich markup which Rich may not pass through cleanly (`commands.py:329-331`). Floods terminal with progress lines on long streams. **Fix:** Use `rich.progress.Progress`.
- **[LOW-C-2]** No `--no-color` / `--color` CLI flag (`main.py:15-16`). `NO_COLOR` env works but is undocumented.
- **[LOW-C-3]** README's "Custom Parser" example imports from `ulp.core.base` / `ulp.core.models` instead of the public `ulp` namespace (`README.md:221-222`). Couples users to internal paths.
- **[LOW-C-4]** `ulp[geoip]` extra is advertised but no CLI option exposes GeoIP enrichment (`README.md:29-30`). Library-only feature should be documented as such.
- **[LOW-C-5]** `correlate` table caps at 50 groups silently (`commands.py:284`). Summary says "Groups found: 200", table shows 50, no truncation notice. **Fix:** Print a truncation hint.
- **[LOW-C-6]** `detect` with no files exits 1 instead of click-standard 2 (`main.py:258-259`). **Fix:** `raise click.UsageError(...)`.

### Tests / CI / Docs
- **[LOW-T-1]** CI runs Linux only (`.github/workflows/ci.yml:13`). Classifier declares OS Independent but no Windows/macOS coverage.
- **[LOW-T-2]** `test_parse_no_files` asserts loosely against three possible substrings without pinning exit code (`tests/test_cli.py:153-160`).
- **[LOW-T-3]** Several tests use `datetime.now()` directly (`tests/test_infrastructure.py:182,215`; `tests/test_domain.py:157,176`). No freezing. Fragile if assertions tighten in the future.

---

## Verified defenses and correct behaviors

These were specifically checked and found to be implemented correctly. Listed so a reader can see what was inspected versus glossed over:

**Security**
- CSV formula injection: `sanitize_csv_cell` is correctly applied to every user-data column (`message`, `source_file`, `service`) in `render_csv` (`output.py:121-130`). Header row present.
- `--grep` user input is routed through `validate_regex_pattern` (`commands.py:152-159`); `SecurityValidationError` is caught and reported.
- `MAX_ORPHAN_ENTRIES` enforced in `RequestIdCorrelation` (`strategies.py:106-115`) — one-time warning, silent drop after.
- `MAX_SESSION_GROUPS` enforced in `SessionCorrelation` (`strategies.py:368-377`).
- `validate_line_length` called in `FileStreamSource`, `LargeFileStreamSource._read_lines_regular`, and `ChunkedFileStreamSource`. (Gap on mmap-accumulation path — see CRIT-3 — and stdin — see HIGH-S-1.)
- No archive/zip handling exists (no zip-slip / decompression-bomb risk).
- No `--output` file-path write capability (no arbitrary-write surface).

**Parser correctness**
- IPv6 source IPs in Apache/Nginx fields parse correctly via `\S+`.
- Apache `response_size="-"` is correctly mapped to `None` instead of crashing.
- Docker `stderr` stream defaults to `WARNING` when inferred level is `INFO`.
- RFC5424 priority decoding (`facility = pri >> 3`, `severity = pri & 0x07`) is correct.
- `klog` (Kubernetes component) parser implements year rollover correctly — pattern to mirror in [HIGH-P-5].
- RFC5424 `NILVALUE` (`-`) is correctly handled for timestamp, hostname, appname, procid, msgid, SD.
- `BaseParser.parse_stream` skips empty/whitespace-only lines without producing spurious entries.
- All parsers return `LogEntry` with `parse_errors` populated on malformed input rather than raising — **except** `KubernetesAuditParser` on null `responseStatus` (CRIT-8).
- No duplicate format names across all 37 registered format strings (Counter check).

**Infrastructure**
- mmap on files ≤ 100 MB is correctly avoided (`_use_mmap` check).
- `mmap.ACCESS_READ` is cross-platform (Linux + Windows).
- mmap context manager closes both `mm` and file handle even on generator early-close.
- File handles released on exception across all three file sources (with-statements).
- `RequestIdCorrelation` orphan bound, `SessionCorrelation` session-count bound, and `TimestampWindowCorrelation` buffer cap are individually correct (the cross-cutting issue is buffer-split semantics — HIGH-A-1).
- `BufferedStdinSource` for-else avoids a second pass over exhausted stdin.
- `FormatDetectorAdapter` and `ParserRegistryAdapter` are thin delegations with no duplicated logic.
- `NormalizationPipeline.process` is a true generator (modulo CRIT-6 in its exception handler).
- `FieldNormalizer` defensively copies `DEFAULT_MAPPINGS`.

**CLI / Display**
- Rich auto-detects TTY and disables color when stdout is not a tty; `NO_COLOR` env var honored.
- `pyproject.toml` entry point `ulp = "ulp.cli.main:cli"` resolves correctly.
- `--strategy all` matches the public `correlate()` strategy composition.
- `render_table` truncates messages > 200 chars to `197...` and uses `overflow="fold"`.
- `--output` per-command choices are justified (CSV/table buffer-only; stream restricted to compact/json).
- `ulp formats` correctly enumerates `registry.list_parsers()` without fabrication.
- `correlate` requires ≥ 2 files via `required=True` and an explicit guard.

**Application / Domain**
- `parse_file` line-number enrichment is intentional and correct (parser leaves it None; reader fills in).
- `stream_parse()` is a true generator (`yield from`); no accidental accumulation.
- `to_dict`/`from_dict` round-trip works for the fields it does cover (UUID, tz-aware datetime, nested dicts) — but coverage gaps (HIGH-T-6) and the CRIT-5 KeyError limit confidence.
- `CorrelationGroup.sources` only recomputed when explicit value not provided.
- `ParseResult.filter(level=ERROR)` correctly excludes `UNKNOWN` (whose value is `-1`).
- `TimestampWindowCorrelation.supports_streaming()` is implemented and the strategy emits as windows close.
- Exception hierarchy is well-structured (`ParseError` includes `line`, `line_number`, `parser_name`).
- No threading or async code anywhere — no concurrency bugs possible in current paths.

**Tests / CI / Docs (positives)**
- LICENSE / pyproject classifier / `[project] license` all agree on MIT.
- Python matrix `[3.10, 3.11, 3.12, 3.13]` matches `requires-python` and classifiers exactly.
- Publish workflow uses PyPI OIDC trusted publishing with `id-token: write` and a named `pypi` environment.
- `publish.yml` is release-triggered.
- All four CI jobs run pytest, ruff (check + format --check), and mypy (modulo MED-T-1).
- `internal_docs/`, `crash_logs/` are gitignored and not present in the repo.
- README badges target the correct URLs.

---

## Appendix — Phase 1 plan (preserved as executed)

```
Phase 1: Opus — Planning
  ├── Inventory ~6,100 LOC across src/ulp/{cli, core, application, domain, infrastructure, parsers, detection}
  ├── Partition into 6 non-overlapping review streams (S, P, A, I, C, T)
  ├── Define severity rubric (Critical / High / Medium / Low)
  └── Define reporting contract (file:line, category, evidence, impact, remediation)

Phase 2: Sonnet — Parallel execution
  ├── A. Security & Input Validation  (run_in_background)
  ├── B. Parser Correctness            (run_in_background)
  ├── C. Application & Domain Logic    (run_in_background)
  ├── D. Infrastructure & Streaming    (run_in_background)
  ├── E. CLI & Display                 (run_in_background)
  └── F. Tests, Packaging, CI, Docs    (run_in_background)

Phase 3: Opus — Consolidation
  ├── Deduplicate cross-stream findings (mmap unbounded, stdin no-bound, correlation buffer-split, dead UnicodeDecodeError handler, LogLevel "f", TimestampNormalizer naive)
  ├── Reconcile severity where streams disagreed (always take the stronger, evidenced rating)
  ├── Cross-link related findings (e.g., CRIT-7 + HIGH-P-1; CRIT-1 + CRIT-2 + CRIT-3 + HIGH-T-2)
  └── Surface highest-leverage repairs in the executive summary
```
