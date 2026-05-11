"""
Generic fallback parser for unrecognized log formats.
"""

import re
from datetime import datetime

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel

__all__ = ["GenericParser"]


class GenericParser(BaseParser):
    """
    Fallback parser for logs that don't match any known format.

    Attempts to extract basic information:
    - Timestamp (if recognizable pattern found)
    - Log level (if common keywords found)
    - Message (the full line or remainder after timestamp)
    """

    name = "generic"
    supported_formats = ["generic", "unknown", "text"]

    # Common timestamp patterns to try
    TIMESTAMP_PATTERNS = [
        # ISO 8601
        (r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*', "%Y-%m-%dT%H:%M:%S"),
        # Common datetime
        (r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?)\s*', "%Y-%m-%d %H:%M:%S"),
        # Date with slashes
        (r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s*', "%Y/%m/%d %H:%M:%S"),
        # US format
        (r'^(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s*', "%m/%d/%Y %H:%M:%S"),
        # Time only
        (r'^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*', "%H:%M:%S"),
        # Unix timestamp (seconds)
        (r'^(\d{10})\s*', "unix"),
        # Unix timestamp (milliseconds)
        (r'^(\d{13})\s*', "unix_ms"),
    ]

    # Compile patterns
    _compiled_ts_patterns = [(re.compile(p), f) for p, f in TIMESTAMP_PATTERNS]

    # Level keywords to search for
    LEVEL_PATTERNS = [
        (re.compile(r'\b(EMERG|EMERGENCY)\b', re.I), LogLevel.EMERGENCY),
        (re.compile(r'\b(ALERT)\b', re.I), LogLevel.ALERT),
        (re.compile(r'\b(CRIT|CRITICAL|FATAL)\b', re.I), LogLevel.CRITICAL),
        (re.compile(r'\b(ERR|ERROR)\b', re.I), LogLevel.ERROR),
        (re.compile(r'\b(WARN|WARNING)\b', re.I), LogLevel.WARNING),
        (re.compile(r'\b(NOTICE)\b', re.I), LogLevel.NOTICE),
        (re.compile(r'\b(INFO)\b', re.I), LogLevel.INFO),
        (re.compile(r'\b(DEBUG|TRACE|VERBOSE)\b', re.I), LogLevel.DEBUG),
    ]

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single line using generic heuristics."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name
        entry.format_detected = "generic"
        entry.parser_confidence = 0.3  # Low confidence for fallback

        stripped = line.strip()
        message = stripped

        # Try to extract timestamp
        for pattern, fmt in self._compiled_ts_patterns:
            match = pattern.match(stripped)
            if match:
                ts_str = match.group(1)
                entry.timestamp = self._parse_generic_timestamp(ts_str, fmt)
                if entry.timestamp:
                    # Remove timestamp from message
                    message = stripped[match.end():].strip()
                    entry.timestamp_precision = "s"
                    entry.parser_confidence = 0.5
                    break

        # Try to extract level
        for pattern, level in self.LEVEL_PATTERNS:
            if pattern.search(message):
                entry.level = level
                entry.parser_confidence = min(entry.parser_confidence + 0.2, 0.7)
                break

        # If no level found, try to infer from message content
        if entry.level == LogLevel.UNKNOWN:
            entry.level = self._infer_level_from_message(message)

        entry.message = message

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """
        Generic parser can always parse, but with low confidence.

        Returns a low confidence to ensure format-specific parsers are preferred.
        """
        # Check if any lines have recognizable structure
        has_timestamp = 0
        has_level = 0

        for line in sample:
            line = line.strip()
            if not line:
                continue

            # Check for timestamp patterns
            for pattern, _ in self._compiled_ts_patterns:
                if pattern.match(line):
                    has_timestamp += 1
                    break

            # Check for level patterns
            for pattern, _ in self.LEVEL_PATTERNS:
                if pattern.search(line):
                    has_level += 1
                    break

        # Calculate confidence based on recognizable patterns
        if not sample:
            return 0.3

        ts_ratio = has_timestamp / len(sample)
        level_ratio = has_level / len(sample)

        # Base confidence of 0.3, plus bonus for recognizable patterns
        return min(0.3 + (ts_ratio * 0.2) + (level_ratio * 0.1), 0.6)

    def _parse_generic_timestamp(self, ts_str: str, fmt: str) -> datetime | None:
        """Parse timestamp with given format."""
        if fmt == "unix":
            try:
                return datetime.fromtimestamp(int(ts_str))
            except (ValueError, OSError):
                return None

        if fmt == "unix_ms":
            try:
                return datetime.fromtimestamp(int(ts_str) / 1000)
            except (ValueError, OSError):
                return None

        # Try the specified format
        try:
            # Handle milliseconds with comma
            if ",%f" not in fmt and "," in ts_str:
                ts_str = ts_str.replace(",", ".")

            # Handle ISO 8601 timezone
            if "T" in ts_str:
                ts_str = ts_str.replace("Z", "+00:00")
                # dateutil handles this better
                return self._parse_timestamp(ts_str)

            return datetime.strptime(ts_str.split(".")[0], fmt)
        except ValueError:
            return None
