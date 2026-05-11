"""
JSON/JSONL log parser.
"""

import json
from typing import Any

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel, CorrelationIds, LogSource
from ulp.core.security import validate_json_depth, SecurityValidationError

__all__ = ["JSONParser"]


class JSONParser(BaseParser):
    """
    Parse JSON-formatted structured logs (JSONL/NDJSON).

    Handles common field naming conventions across different logging libraries.
    """

    name = "json"
    supported_formats = ["json_structured", "json_lines", "ndjson", "json"]

    # Common field names for timestamp
    TIMESTAMP_FIELDS = [
        "timestamp", "time", "@timestamp", "ts", "datetime",
        "created", "date", "logged_at", "log_time"
    ]

    # Common field names for level
    LEVEL_FIELDS = [
        "level", "severity", "loglevel", "log_level", "lvl",
        "levelname", "priority"
    ]

    # Common field names for message
    MESSAGE_FIELDS = [
        "message", "msg", "text", "log", "body",
        "content", "event", "description"
    ]

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single JSON log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError as e:
            entry.parse_errors.append(f"JSON decode error: {e}")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        if not isinstance(data, dict):
            entry.parse_errors.append("JSON is not an object")
            entry.message = str(data)
            entry.parser_confidence = 0.3
            return entry

        # H4: Validate JSON depth to prevent stack overflow
        try:
            validate_json_depth(data)
        except SecurityValidationError as e:
            entry.parse_errors.append(f"JSON security validation failed: {e.message}")
            entry.message = line[:200] + "..." if len(line) > 200 else line
            entry.parser_confidence = 0.1
            return entry

        entry.format_detected = "json_structured"
        entry.parser_confidence = 1.0
        entry.structured_data = data

        # Extract timestamp
        for field in self.TIMESTAMP_FIELDS:
            if field in data:
                ts = self._parse_timestamp(str(data[field]))
                if ts:
                    entry.timestamp = ts
                    entry.timestamp_precision = self._detect_precision(str(data[field]))
                break

        # Extract level
        for field in self.LEVEL_FIELDS:
            if field in data:
                entry.level = LogLevel.from_string(str(data[field]))
                break

        # Extract message
        for field in self.MESSAGE_FIELDS:
            if field in data:
                entry.message = str(data[field])
                break

        # If no message found, create summary from data
        if not entry.message:
            entry.message = self._create_message_summary(data)

        # Extract correlation IDs
        entry.correlation = self._extract_correlation(data)

        # Extract source info
        entry.source = self._extract_source(data)

        # Store remaining fields as extra
        known_fields = set(
            self.TIMESTAMP_FIELDS + self.LEVEL_FIELDS + self.MESSAGE_FIELDS
        )
        entry.extra = {k: v for k, v in data.items() if k not in known_fields}

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing JSON logs."""
        if not sample:
            return 0.0

        json_count = 0
        has_log_fields = 0

        for line in sample:
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    json_count += 1
                    # Check for common log fields
                    if any(f in data for f in self.TIMESTAMP_FIELDS + self.LEVEL_FIELDS + self.MESSAGE_FIELDS):
                        has_log_fields += 1
            except json.JSONDecodeError:
                pass

        if not sample:
            return 0.0

        json_ratio = json_count / len(sample)

        # Bonus if it has typical log fields
        if has_log_fields > 0:
            field_bonus = min(0.2, has_log_fields / len(sample) * 0.3)
            return min(1.0, json_ratio + field_bonus)

        return json_ratio * 0.8  # Slight penalty if no log fields found

    def _extract_correlation(self, data: dict[str, Any]) -> CorrelationIds:
        """Extract correlation IDs from JSON data."""
        def get_field(*names: str) -> str | None:
            for name in names:
                if name in data:
                    return str(data[name])
            return None

        return CorrelationIds(
            request_id=get_field("request_id", "requestId", "req_id", "x-request-id"),
            trace_id=get_field("trace_id", "traceId", "x-trace-id", "traceid"),
            span_id=get_field("span_id", "spanId", "x-span-id"),
            correlation_id=get_field("correlation_id", "correlationId", "x-correlation-id"),
            session_id=get_field("session_id", "sessionId", "session"),
            user_id=get_field("user_id", "userId", "user", "username"),
            transaction_id=get_field("transaction_id", "transactionId", "txn_id"),
        )

    def _extract_source(self, data: dict[str, Any]) -> LogSource:
        """Extract source information from JSON data."""
        def get_field(*names: str) -> str | None:
            for name in names:
                if name in data:
                    return str(data[name])
            return None

        return LogSource(
            hostname=get_field("hostname", "host", "server", "node"),
            service=get_field("service", "app", "application", "logger", "name"),
            container_id=get_field("container_id", "containerId", "container"),
            pod_name=get_field("pod_name", "podName", "pod"),
            namespace=get_field("namespace", "ns"),
        )

    def _detect_precision(self, timestamp_str: str) -> str:
        """Detect timestamp precision from string format."""
        if "." in timestamp_str:
            # Count decimal places
            decimal_part = timestamp_str.split(".")[-1].rstrip("Z")
            decimal_places = len(decimal_part)
            if decimal_places >= 9:
                return "ns"
            elif decimal_places >= 6:
                return "us"
            elif decimal_places >= 3:
                return "ms"
        return "s"

    def _create_message_summary(self, data: dict[str, Any]) -> str:
        """Create a summary message from JSON data."""
        # Try to create a meaningful summary
        parts = []
        for key in ["event", "action", "type", "status"]:
            if key in data:
                parts.append(f"{key}={data[key]}")

        if parts:
            return ", ".join(parts)

        # Fallback to first few keys
        items = list(data.items())[:3]
        return ", ".join(f"{k}={v}" for k, v in items)
