# Changelog

All notable changes to ULP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-05-11

### Fixed
- PyPI distribution metadata now targets `universal-log-parser`, matching the trusted publisher configuration and avoiding the unrelated `ulp` project name.
- Critical correctness and security fixes from phased application review:
  - mmap streaming path: empty/rotated file crash, byte-by-byte performance, line-length cap bypass
  - `LogEntry.from_dict` no longer raises `KeyError` on unfamiliar level names
  - `NormalizationPipeline.process` error-recovery path now uses `entry.extra` instead of non-existent `entry.metadata`
  - `correlate()` no longer crashes on mixed naive/aware datetimes
  - `KubernetesAuditParser` no longer crashes on `responseStatus: null`
  - Apache and Nginx parsers correctly handle escaped quotes in quoted fields
  - `KubernetesContainerParser` correctly parses CRI-O / containerd format (stream flag stripping; optional sub-second precision)
  - `Z`-suffix timestamps now produce timezone-aware datetimes
  - Format detector correctly prefers `nginx_access` over `apache_combined` for Nginx lines
  - Stdin sources now enforce `MAX_LINE_LENGTH`
  - JSON depth is pre-validated before `json.loads` to prevent C-stack overflow
  - `HostnameEnricher` no longer mutates the process-global socket timeout

### Changed
- `ApacheCombinedParser.can_parse` confidence is capped at 1.0 (was previously up to 1.1)
- CLI `--level` choices expanded to include trace, notice, alert, emergency
- CLI `--limit` requires a positive integer
- CLI `--window` requires a positive float
- CLI `stream` command writes progress and summary to stderr (was stdout, corrupted piped JSON)
- CLI `parse`/`stream`/`detect`/`correlate` accept `-` as filename for stdin input

### Added
- `safe_json_loads()` in `ulp.core.security` performs a pre-parse depth check
- `GeoIPEnricher` exposes `close()` and supports the context-manager protocol
- Test coverage for Docker / Kubernetes parsers, stdin sources, mmap branch, correlation bounds, and full `LogEntry` round-trip serialization

## [0.2.0] - 2026-01-27
- Initial release of Universal Log Parser
- Streaming support for 1-10 GB+ files
- Cross-source log correlation (request_id, timestamp, session strategies)
- 10+ format auto-detection (JSON, Apache, Nginx, Syslog, Python logging, Docker, Kubernetes, etc.)
- Clean architecture with domain/application/infrastructure layers
- Optional GeoIP enrichment via `ulp[geoip]`
