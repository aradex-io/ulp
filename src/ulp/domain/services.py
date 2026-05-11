"""
Domain service protocols for ULP.

These define the interfaces (ports) that the application layer uses.
Infrastructure adapters implement these protocols.
"""

from abc import ABC, abstractmethod
from typing import Protocol, Iterator, runtime_checkable
from ulp.domain.entities import LogEntry, CorrelationGroup

__all__ = [
    "StreamProcessor",
    "NormalizationStep",
    "CorrelationStrategy",
    "LogParser",
    "LogSourcePort",
]


class StreamProcessor(ABC):
    """
    Domain service for processing log streams.

    Implementations can filter, transform, or normalize entries.
    """

    @abstractmethod
    def process(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        """
        Process a stream of log entries.

        Args:
            entries: Input stream of log entries

        Yields:
            Processed log entries
        """
        pass


@runtime_checkable
class NormalizationStep(Protocol):
    """
    Protocol for normalization pipeline steps.

    Each step is a pure function that transforms a LogEntry.
    """

    def normalize(self, entry: LogEntry) -> LogEntry:
        """
        Normalize a single log entry.

        Args:
            entry: Entry to normalize

        Returns:
            Normalized entry (may be same object or new)
        """
        ...


class CorrelationStrategy(ABC):
    """
    Base class for correlation strategies.

    Different strategies correlate logs in different ways:
    - RequestIdCorrelation: By matching request/trace IDs
    - TimestampWindowCorrelation: By time proximity
    - SessionCorrelation: By user session
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of this correlation strategy."""
        pass

    @abstractmethod
    def correlate(
        self,
        entries: Iterator[LogEntry] | list[LogEntry],
        buffer_size: int = 10000
    ) -> Iterator[CorrelationGroup]:
        """
        Correlate entries using this strategy.

        Args:
            entries: Log entries to correlate
            buffer_size: Maximum entries to buffer (for memory management)

        Yields:
            Correlation groups as they are identified
        """
        pass

    @abstractmethod
    def supports_streaming(self) -> bool:
        """
        Whether this strategy can work with streaming input.

        Streaming strategies can emit groups before seeing all input.
        Non-streaming strategies must buffer all entries first.
        """
        pass


@runtime_checkable
class LogParser(Protocol):
    """
    Protocol for log parsers.

    Parsers convert raw log lines into normalized LogEntry objects.
    """

    name: str
    supported_formats: list[str]

    def parse_line(self, line: str) -> LogEntry:
        """
        Parse a single log line.

        Args:
            line: Raw log line to parse

        Returns:
            Normalized LogEntry
        """
        ...

    def can_parse(self, sample: list[str]) -> float:
        """
        Determine confidence that this parser can handle the sample.

        Args:
            sample: Sample of log lines

        Returns:
            Confidence score from 0.0 to 1.0
        """
        ...

    def parse_stream(self, lines: Iterator[str]) -> Iterator[LogEntry]:
        """
        Parse a stream of log lines.

        Args:
            lines: Iterator of log lines

        Yields:
            Parsed LogEntry for each line
        """
        ...


@runtime_checkable
class LogSourcePort(Protocol):
    """
    Protocol for log source adapters (ports).

    Implementations provide log lines from various sources:
    - Files (including large files with memory mapping)
    - Stdin
    - Network streams
    - Cloud services
    """

    def read_lines(self) -> Iterator[str]:
        """
        Read raw log lines from the source.

        Yields:
            Raw log lines (may or may not include newlines)
        """
        ...

    def metadata(self) -> dict[str, str]:
        """
        Get source metadata.

        Returns:
            Dictionary with source information (path, type, size, etc.)
        """
        ...


class FormatDetector(Protocol):
    """
    Protocol for format detection.

    Implementations analyze log samples to determine the format.
    """

    def detect(self, lines: list[str]) -> tuple[str, float]:
        """
        Detect the format of the given sample.

        Args:
            lines: Sample of log lines

        Returns:
            Tuple of (format_name, confidence)
        """
        ...

    def detect_all(self, lines: list[str]) -> list[tuple[str, float]]:
        """
        Detect all possible formats with confidence scores.

        Args:
            lines: Sample of log lines

        Returns:
            List of (format_name, confidence) tuples, sorted by confidence
        """
        ...
