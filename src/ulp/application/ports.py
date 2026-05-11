"""
Port interfaces for the application layer.

These are the interfaces that infrastructure adapters must implement.
They define the contract between use cases and the outside world.
"""

from typing import Protocol, Iterator, runtime_checkable
from ulp.domain.entities import LogEntry

__all__ = [
    "LogSourcePort",
    "ParserRegistry",
    "FormatDetectorPort",
    "NormalizerPort",
]


@runtime_checkable
class LogSourcePort(Protocol):
    """
    Port for log source adapters.

    Implementations provide log lines from various sources:
    - Files (including large files with memory mapping)
    - Stdin
    - Network streams
    """

    def read_lines(self) -> Iterator[str]:
        """Read raw log lines from the source."""
        ...

    def metadata(self) -> dict[str, str]:
        """Get source metadata (path, type, size, etc.)."""
        ...


@runtime_checkable
class ParserPort(Protocol):
    """
    Port for log parsers.

    Implementations parse raw log lines into LogEntry objects.
    """

    name: str
    supported_formats: list[str]

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single log line."""
        ...

    def can_parse(self, sample: list[str]) -> float:
        """Return confidence score (0-1) for parsing this sample."""
        ...

    def parse_stream(self, lines: Iterator[str]) -> Iterator[LogEntry]:
        """Parse a stream of log lines."""
        ...


class ParserRegistry(Protocol):
    """
    Port for parser registry.

    Manages available parsers and provides lookup by format name.
    """

    def get_parser(self, format_name: str) -> ParserPort | None:
        """Get parser instance for the given format."""
        ...

    def get_best_parser(self, sample: list[str]) -> tuple[ParserPort | None, float]:
        """Find the best parser for the given sample."""
        ...

    def list_parsers(self) -> list[str]:
        """List all registered parser names."""
        ...

    def list_formats(self) -> list[str]:
        """List all supported format names."""
        ...


class FormatDetectorPort(Protocol):
    """
    Port for format detection.

    Implementations analyze log samples to determine the format.
    """

    def detect(self, lines: list[str]) -> tuple[str, float]:
        """Detect the format of the given sample."""
        ...

    def detect_file(self, file_path: str) -> tuple[str, float]:
        """Detect the format of a file."""
        ...

    def detect_all(self, lines: list[str]) -> list[tuple[str, float]]:
        """Detect all possible formats with confidence scores."""
        ...


class NormalizerPort(Protocol):
    """
    Port for normalization pipeline.

    Implementations apply normalization steps to log entries.
    """

    def process(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        """Process a stream of entries through normalization."""
        ...

    def process_one(self, entry: LogEntry) -> LogEntry:
        """Process a single entry."""
        ...
