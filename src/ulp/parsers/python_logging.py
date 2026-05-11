"""
Python standard logging format parser.
"""

import re

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel, LogSource

__all__ = ["PythonLoggingParser"]


class PythonLoggingParser(BaseParser):
    """
    Parse Python standard logging format.

    Default format: %(asctime)s - %(name)s - %(levelname)s - %(message)s
    Which produces: 2026-01-27 10:15:32,123 - myapp.module - INFO - Message here

    Also handles common variations:
    - With thread: %(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] - %(message)s
    - Simple: %(levelname)s:%(name)s:%(message)s
    """

    name = "python_logging"
    supported_formats = ["python_logging", "python_default", "python"]

    # Primary pattern: timestamp - name - level - message
    PATTERN_FULL = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})\s+'
        r'[-:]\s*'
        r'(?P<name>\S+)\s+'
        r'[-:]\s*'
        r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+'
        r'[-:]\s*'
        r'(?P<message>.*)'
    )

    # Alternate pattern: timestamp level name message
    PATTERN_ALT = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})\s+'
        r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+'
        r'(?P<name>\S+)\s+'
        r'(?P<message>.*)'
    )

    # Simple pattern: LEVEL:name:message
    PATTERN_SIMPLE = re.compile(
        r'^(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL):(?P<name>\S+):(?P<message>.*)'
    )

    # Pattern with thread info
    PATTERN_THREADED = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d{3})\s+'
        r'[-:]\s*'
        r'(?P<name>\S+)\s+'
        r'[-:]\s*'
        r'(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+'
        r'[-:]\s*'
        r'\[(?P<thread>[^\]]+)\]\s+'
        r'[-:]\s*'
        r'(?P<message>.*)'
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single Python logging line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        # Try patterns in order of specificity
        for pattern in [self.PATTERN_THREADED, self.PATTERN_FULL, self.PATTERN_ALT, self.PATTERN_SIMPLE]:
            match = pattern.match(line.strip())
            if match:
                return self._build_entry(entry, match.groupdict())

        # No pattern matched
        entry.parse_errors.append("Line does not match Python logging format")
        entry.message = line
        entry.parser_confidence = 0.0
        return entry

    def _build_entry(self, entry: LogEntry, d: dict) -> LogEntry:
        """Build LogEntry from matched groups."""
        entry.format_detected = "python_logging"
        entry.parser_confidence = 0.95

        # Parse timestamp if present
        if d.get("timestamp"):
            entry.timestamp = self._parse_python_timestamp(d["timestamp"])
            if entry.timestamp:
                entry.timestamp_precision = "ms"

        # Parse level
        entry.level = LogLevel.from_string(d["level"])

        # Set message
        entry.message = d["message"]

        # Set source (logger name)
        entry.source = LogSource(service=d.get("name"))

        # Store thread info if present
        if d.get("thread"):
            entry.extra["thread"] = d["thread"]

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Python logging."""
        if not sample:
            return 0.0

        matches = 0
        for line in sample:
            line = line.strip()
            if any(p.match(line) for p in [
                self.PATTERN_THREADED, self.PATTERN_FULL,
                self.PATTERN_ALT, self.PATTERN_SIMPLE
            ]):
                matches += 1

        return matches / len(sample)

    def _parse_python_timestamp(self, ts: str):
        """
        Parse Python logging timestamp.

        Formats:
        - 2026-01-27 10:15:32,123 (comma before milliseconds)
        - 2026-01-27 10:15:32.123 (dot before milliseconds)
        """
        from datetime import datetime

        # Try comma format first (default)
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S,%f")
        except ValueError:
            pass

        # Try dot format
        try:
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            pass

        return None
