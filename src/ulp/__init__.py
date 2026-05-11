"""
Universal Log Parser (ULP) - Automatically detect, parse, and normalize logs from any format.

Now with streaming support for large files (1-10GB+) and cross-source log correlation.

Usage:
    from ulp import parse, detect_format, LogEntry, LogLevel

    # Detect format
    format_name, confidence = detect_format("access.log")

    # Parse a file
    entries = parse("access.log")

    # Parse with specific format
    entries = parse("app.log", format="json_structured")

    # Streaming parse for large files
    from ulp import stream_parse
    for entry in stream_parse("huge.log", format="json"):
        process(entry)

    # Correlate logs across multiple sources
    from ulp import correlate
    result = correlate(["app.log", "nginx.log"], strategy="request_id")
"""

__version__ = "0.2.0"

from ulp.core.models import (
    LogEntry,
    LogLevel,
    LogSource,
    NetworkInfo,
    HTTPInfo,
    CorrelationIds,
    ParseResult,
    FormatSignature,
)
from ulp.core.base import BaseParser
from ulp.core.exceptions import (
    ULPError,
    ParseError,
    FormatDetectionError,
    ConfigurationError,
)
from ulp.detection.detector import FormatDetector
from ulp.parsers import ParserRegistry, registry

# Domain entities (clean architecture)
from ulp.domain.entities import (
    CorrelationGroup,
    CorrelationResult,
)

# Infrastructure adapters
from ulp.infrastructure import (
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

__all__ = [
    # Version
    "__version__",
    # Core models
    "LogEntry",
    "LogLevel",
    "LogSource",
    "NetworkInfo",
    "HTTPInfo",
    "CorrelationIds",
    "ParseResult",
    "FormatSignature",
    # Domain entities
    "CorrelationGroup",
    "CorrelationResult",
    # Base classes
    "BaseParser",
    # Exceptions
    "ULPError",
    "ParseError",
    "FormatDetectionError",
    "ConfigurationError",
    # Detection
    "FormatDetector",
    # Registry
    "ParserRegistry",
    "registry",
    # Sources
    "FileStreamSource",
    "LargeFileStreamSource",
    "ChunkedFileStreamSource",
    "StdinStreamSource",
    "BufferedStdinSource",
    # Correlation
    "RequestIdCorrelation",
    "TimestampWindowCorrelation",
    "SessionCorrelation",
    # Normalization
    "NormalizationPipeline",
    "TimestampNormalizer",
    "LevelNormalizer",
    "FieldNormalizer",
    # Convenience functions
    "parse",
    "parse_file",
    "detect_format",
    "stream_parse",
    "correlate",
]


def detect_format(file_path: str) -> tuple[str, float]:
    """
    Detect the log format of a file.

    Args:
        file_path: Path to the log file

    Returns:
        Tuple of (format_name, confidence) where confidence is 0.0-1.0
    """
    detector = FormatDetector()
    return detector.detect_file(file_path)


def parse_file(file_path: str, format: str | None = None) -> list[LogEntry]:
    """
    Parse a log file and return normalized LogEntry objects.

    Args:
        file_path: Path to the log file
        format: Optional format name to force specific parser

    Returns:
        List of LogEntry objects
    """
    if format is None:
        format_name, _ = detect_format(file_path)
    else:
        format_name = format

    parser = registry.get_parser(format_name)
    if parser is None:
        parser = registry.get_parser("generic")

    entries = []
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if line.strip():
                entry = parser.parse_line(line)
                entry.source.file_path = file_path
                entry.source.line_number = i
                entries.append(entry)

    return entries


# Alias for convenience
parse = parse_file


def stream_parse(
    file_path: str,
    format: str,
    progress_callback=None,
):
    """
    Stream-parse a log file for minimal memory usage.

    Use this for very large files (1-10GB+) where buffering isn't feasible.

    Args:
        file_path: Path to the log file
        format: Format name (required - no auto-detection for streaming)
        progress_callback: Optional callback(bytes_read, total_bytes, lines_read)

    Yields:
        LogEntry objects as they are parsed

    Example:
        for entry in stream_parse("huge.log", format="json"):
            if entry.level >= LogLevel.ERROR:
                print(entry.message)
    """
    from ulp.application.parse_logs import ParseLogsStreamingUseCase
    from ulp.infrastructure.adapters import ParserRegistryAdapter

    # Choose source based on file size
    from pathlib import Path
    file_size = Path(file_path).stat().st_size

    if file_size > 100 * 1024 * 1024:  # > 100MB
        if progress_callback:
            source = ChunkedFileStreamSource(
                file_path,
                progress_callback=progress_callback
            )
        else:
            source = LargeFileStreamSource(file_path)
    else:
        source = FileStreamSource(file_path)

    registry_adapter = ParserRegistryAdapter()
    use_case = ParseLogsStreamingUseCase(
        source=source,
        parser_registry=registry_adapter,
    )

    yield from use_case.execute(format_name=format)


def correlate(
    file_paths: list[str],
    strategy: str = "request_id",
    format: str | None = None,
    window_seconds: float = 1.0,
) -> CorrelationResult:
    """
    Correlate log entries across multiple files.

    Groups related log entries by request ID, timestamp proximity,
    or session identifier.

    Args:
        file_paths: List of log file paths
        strategy: Correlation strategy ("request_id", "timestamp", "session", "all")
        format: Optional format name (auto-detect if not specified)
        window_seconds: Time window for timestamp correlation

    Returns:
        CorrelationResult with groups and orphan entries

    Example:
        result = correlate(["app.log", "nginx.log"], strategy="request_id")
        for group in result.groups:
            print(f"Request {group.correlation_key}: {len(group.entries)} entries")
    """
    from ulp.application.parse_logs import ParseLogsUseCase
    from ulp.application.correlate_logs import CorrelateLogsUseCase
    from ulp.infrastructure.adapters import FormatDetectorAdapter, ParserRegistryAdapter

    detector = FormatDetectorAdapter()
    registry_adapter = ParserRegistryAdapter()

    # Build correlation strategies
    strategies = []
    if strategy == "request_id" or strategy == "all":
        strategies.append(RequestIdCorrelation())
    if strategy == "timestamp" or strategy == "all":
        strategies.append(TimestampWindowCorrelation(window_seconds=window_seconds))
    if strategy == "session" or strategy == "all":
        strategies.append(SessionCorrelation())

    if not strategies:
        raise ValueError(f"Unknown correlation strategy: {strategy}")

    # Create entry iterators for each file
    entry_iterators = []
    for file_path in file_paths:
        source = FileStreamSource(file_path)
        use_case = ParseLogsUseCase(
            source=source,
            parser_registry=registry_adapter,
            format_detector=detector,
        )
        entry_iterators.append(use_case.execute(format_hint=format))

    # Execute correlation
    correlate_use_case = CorrelateLogsUseCase(
        strategies=strategies,
        window_size=10000,
    )

    return correlate_use_case.execute(entry_iterators)
