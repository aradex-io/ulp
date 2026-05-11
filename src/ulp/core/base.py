"""
Base parser class and protocol for ULP parsers.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator
import re

from dateutil import parser as dateutil_parser

from ulp.core.models import LogEntry, LogLevel

__all__ = ["BaseParser"]


# Common timestamp formats to try
TIMESTAMP_FORMATS = [
    # ISO 8601 variants
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
    # Common log formats
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S,%f",  # Python logging
    "%Y-%m-%d %H:%M:%S",
    # Apache/Nginx CLF format
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    # Syslog
    "%b %d %H:%M:%S",
    # Nginx error log
    "%Y/%m/%d %H:%M:%S",
    # Other common formats
    "%d-%m-%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


class BaseParser(ABC):
    """
    Base class for all log parsers.

    Subclasses must implement:
        - parse_line(line: str) -> LogEntry
        - can_parse(sample: list[str]) -> float

    Optionally override:
        - parse_stream(lines: Iterator[str]) -> Iterator[LogEntry]

    Attributes:
        name: Unique identifier for this parser
        supported_formats: List of format names this parser handles
    """

    name: str = "base"
    supported_formats: list[str] = []

    def __init__(self):
        """Initialize the parser."""
        self._compiled_patterns: dict[str, re.Pattern] = {}

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry:
        """
        Parse a single log line into a LogEntry.

        This method should never raise exceptions - instead, return
        a LogEntry with parse_errors populated.

        Args:
            line: Raw log line to parse

        Returns:
            LogEntry with extracted fields
        """
        pass

    @abstractmethod
    def can_parse(self, sample: list[str]) -> float:
        """
        Determine confidence that this parser can handle the given sample.

        Args:
            sample: List of log lines to analyze

        Returns:
            Confidence score from 0.0 (cannot parse) to 1.0 (perfect match)
        """
        pass

    def parse_stream(self, lines: Iterator[str]) -> Iterator[LogEntry]:
        """
        Parse a stream of log lines.

        Default implementation parses line by line. Override for
        multiline log formats.

        Args:
            lines: Iterator of log lines

        Yields:
            LogEntry for each parsed line
        """
        for line in lines:
            stripped = line.strip()
            if stripped:
                yield self.parse_line(stripped)

    def _parse_timestamp(self, value: str) -> datetime | None:
        """
        Try to parse a timestamp string using multiple formats.

        Args:
            value: Timestamp string to parse

        Returns:
            datetime object or None if parsing fails
        """
        if not value:
            return None

        value = value.strip()

        # Try explicit formats first (faster)
        for fmt in TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        # Fall back to dateutil for fuzzy parsing
        try:
            return dateutil_parser.parse(value, fuzzy=True)
        except (ValueError, TypeError):
            return None

    def _parse_level(self, value: str) -> LogLevel:
        """
        Parse a log level string.

        Args:
            value: Level string to parse

        Returns:
            LogLevel enum value
        """
        return LogLevel.from_string(value)

    def _infer_level_from_message(self, message: str) -> LogLevel:
        """
        Infer log level from message content.

        Args:
            message: Log message to analyze

        Returns:
            Inferred LogLevel or UNKNOWN
        """
        message_lower = message.lower()

        # Check for error indicators
        if any(kw in message_lower for kw in [
            "error", "exception", "failed", "failure", "fatal", "panic"
        ]):
            return LogLevel.ERROR

        # Check for warning indicators
        if any(kw in message_lower for kw in [
            "warn", "warning", "deprecated", "caution"
        ]):
            return LogLevel.WARNING

        # Check for debug indicators
        if any(kw in message_lower for kw in ["debug", "trace", "verbose"]):
            return LogLevel.DEBUG

        return LogLevel.INFO

    def _compile_pattern(self, name: str, pattern: str) -> re.Pattern:
        """
        Compile and cache a regex pattern.

        Args:
            name: Name to cache pattern under
            pattern: Regex pattern string

        Returns:
            Compiled regex pattern
        """
        if name not in self._compiled_patterns:
            self._compiled_patterns[name] = re.compile(pattern)
        return self._compiled_patterns[name]

    def _create_error_entry(self, line: str, error_msg: str) -> LogEntry:
        """
        Create a LogEntry for a line that couldn't be parsed.

        Args:
            line: Original log line
            error_msg: Description of the parse error

        Returns:
            LogEntry with error information
        """
        entry = LogEntry(
            raw=line,
            message=line,
            level=LogLevel.UNKNOWN,
            format_detected="unknown",
            parser_name=self.name,
            parser_confidence=0.0,
        )
        entry.parse_errors.append(error_msg)
        return entry
