"""
Parse logs use case.

Orchestrates log parsing with format detection and normalization.
"""

from typing import Callable, Iterator
from ulp.domain.entities import LogEntry
from ulp.application.ports import LogSourcePort, ParserRegistry, FormatDetectorPort, NormalizerPort

__all__ = ["ParseLogsUseCase"]


class ParseLogsUseCase:
    """
    Use case: Parse logs from a source with format detection.

    Orchestrates: source -> detection -> parsing -> normalization

    This use case handles the complete flow of reading log data,
    detecting its format, parsing it, and optionally normalizing it.

    Example:
        source = FileStreamSource("/var/log/app.log")
        use_case = ParseLogsUseCase(
            source=source,
            parser_registry=registry,
            format_detector=detector,
            normalizer=normalizer  # optional
        )

        for entry in use_case.execute():
            print(f"{entry.timestamp}: {entry.message}")
    """

    def __init__(
        self,
        source: LogSourcePort,
        parser_registry: ParserRegistry,
        format_detector: FormatDetectorPort,
        normalizer: NormalizerPort | None = None
    ):
        """
        Initialize the use case.

        Args:
            source: Log source adapter (file, stdin, etc.)
            parser_registry: Registry of available parsers
            format_detector: Format detection adapter
            normalizer: Optional normalization pipeline
        """
        self.source = source
        self.parser_registry = parser_registry
        self.format_detector = format_detector
        self.normalizer = normalizer

    def execute(
        self,
        format_hint: str | None = None,
        sample_size: int = 50
    ) -> Iterator[LogEntry]:
        """
        Execute the parse logs use case.

        Args:
            format_hint: Optional format name to skip detection
            sample_size: Number of lines to sample for detection

        Yields:
            Normalized LogEntry objects

        Raises:
            ValueError: If no parser is found for the detected format
        """
        # Get lines iterator
        lines_iter = self.source.read_lines()

        # Get source metadata for enrichment
        source_metadata = self.source.metadata()
        source_path = source_metadata.get("path", "<unknown>")

        # Buffer sample for detection
        sample = []
        remaining_lines = []

        for i, line in enumerate(lines_iter):
            if i < sample_size:
                sample.append(line)
            else:
                remaining_lines.append(line)
                break

        # We need to reconstitute the iterator with buffered lines
        def all_lines():
            yield from sample
            yield from remaining_lines
            yield from lines_iter

        # Detect format or use hint
        if format_hint:
            detected_format = format_hint
        else:
            detected_format, confidence = self.format_detector.detect(sample)

        # Get parser
        parser = self.parser_registry.get_parser(detected_format)
        if parser is None:
            parser = self.parser_registry.get_parser("generic")
            if parser is None:
                raise ValueError(f"No parser found for format: {detected_format}")

        # Parse and yield entries
        line_number = 0
        for line in all_lines():
            line_number += 1
            stripped = line.strip()
            if stripped:
                entry = parser.parse_line(stripped)
                entry.source.file_path = source_path
                entry.source.line_number = line_number

                # Apply normalization if configured
                if self.normalizer:
                    entry = self.normalizer.process_one(entry)

                yield entry


class ParseLogsStreamingUseCase:
    """
    Streaming variant of parse logs use case.

    Optimized for very large files (1-10GB) with minimal memory usage.
    Does not buffer samples - requires format to be pre-detected or specified.
    """

    def __init__(
        self,
        source: LogSourcePort,
        parser_registry: ParserRegistry,
        normalizer: NormalizerPort | None = None
    ):
        self.source = source
        self.parser_registry = parser_registry
        self.normalizer = normalizer

    def execute(
        self,
        format_name: str,
        chunk_callback: Callable | None = None
    ) -> Iterator[LogEntry]:
        """
        Execute streaming parse.

        Args:
            format_name: Format name (must be specified, no detection)
            chunk_callback: Optional callback called every N entries

        Yields:
            Parsed LogEntry objects
        """
        parser = self.parser_registry.get_parser(format_name)
        if parser is None:
            raise ValueError(f"No parser found for format: {format_name}")

        source_metadata = self.source.metadata()
        source_path = source_metadata.get("path", "<unknown>")

        line_number = 0
        chunk_count = 0
        chunk_size = 10000

        for line in self.source.read_lines():
            line_number += 1
            stripped = line.strip()
            if stripped:
                entry = parser.parse_line(stripped)
                entry.source.file_path = source_path
                entry.source.line_number = line_number

                if self.normalizer:
                    entry = self.normalizer.process_one(entry)

                yield entry

                chunk_count += 1
                if chunk_callback and chunk_count % chunk_size == 0:
                    chunk_callback(chunk_count, line_number)
