"""
Docker log parsers.

Handles Docker daemon logs and container logs (docker logs output).
"""

import json
import re
from typing import Any

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel

__all__ = ["DockerJSONParser", "DockerDaemonParser"]


class DockerJSONParser(BaseParser):
    """
    Parse Docker container logs in JSON format.

    Docker outputs logs in JSON format when using the json-file logging driver.
    Each line is a JSON object with 'log', 'stream', and 'time' fields.

    Example log:
        {"log":"Starting application...\\n","stream":"stdout","time":"2024-01-15T10:30:00.123456789Z"}
    """

    name = "docker_json"
    supported_formats = ["docker_json", "docker_container"]

    # Docker JSON log pattern
    JSON_PATTERN = re.compile(r'^{.*"log".*"stream".*"time".*}$')

    def parse_line(self, line: str) -> LogEntry:
        """Parse a Docker JSON log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError as e:
            entry.parse_errors.append(f"JSON decode error: {e}")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        if not isinstance(data, dict) or "log" not in data:
            entry.parse_errors.append("Not a Docker JSON log")
            entry.message = line
            entry.parser_confidence = 0.3
            return entry

        entry.format_detected = "docker_json"
        entry.parser_confidence = 1.0

        # Extract log message (strip newline)
        entry.message = data.get("log", "").rstrip("\n")

        # Extract timestamp
        if "time" in data:
            entry.timestamp = self._parse_timestamp(data["time"])
            entry.timestamp_precision = "ns"  # Docker uses nanosecond precision

        # Stream type (stdout/stderr)
        stream = data.get("stream", "stdout")
        entry.structured_data["stream"] = stream

        # stderr often indicates errors
        if stream == "stderr":
            entry.level = self._infer_level_from_message(entry.message)
            if entry.level == LogLevel.INFO:
                entry.level = LogLevel.WARNING  # stderr defaults to warning
        else:
            entry.level = self._infer_level_from_message(entry.message)

        # Store any additional fields
        for key in data:
            if key not in ("log", "stream", "time"):
                entry.structured_data[key] = data[key]

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Docker JSON logs."""
        if not sample:
            return 0.0

        matches = 0
        for line in sample:
            line = line.strip()
            if not line:
                continue
            if self.JSON_PATTERN.match(line):
                try:
                    data = json.loads(line)
                    if "log" in data and "stream" in data and "time" in data:
                        matches += 1
                except json.JSONDecodeError:
                    pass

        if not sample:
            return 0.0

        return matches / len(sample)


class DockerDaemonParser(BaseParser):
    """
    Parse Docker daemon logs (dockerd).

    Docker daemon logs follow a structured format with timestamp,
    level, and component information.

    Example logs:
        time="2024-01-15T10:30:00.123456789Z" level=info msg="Starting up"
        time="2024-01-15T10:30:01Z" level=warning msg="Container unhealthy" container=abc123
    """

    name = "docker_daemon"
    supported_formats = ["docker_daemon", "dockerd"]

    # Pattern for Docker daemon logs (logfmt-style)
    DAEMON_PATTERN = re.compile(
        r'^time="([^"]+)"\s+level=(\w+)\s+msg="([^"]*)"(.*)$'
    )

    # Alternative pattern for systemd journal format
    SYSTEMD_PATTERN = re.compile(
        r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+dockerd\[(\d+)\]:\s+(.*)$'
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a Docker daemon log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        # Try logfmt-style format first
        match = self.DAEMON_PATTERN.match(line.strip())
        if match:
            return self._parse_logfmt(entry, match)

        # Try systemd journal format
        match = self.SYSTEMD_PATTERN.match(line.strip())
        if match:
            return self._parse_systemd(entry, match)

        # Fallback: try to parse as key=value pairs
        return self._parse_keyvalue(entry, line)

    def _parse_logfmt(self, entry: LogEntry, match: re.Match) -> LogEntry:
        """Parse logfmt-style Docker daemon log."""
        timestamp_str, level_str, message, extra = match.groups()

        entry.format_detected = "docker_daemon"
        entry.parser_confidence = 1.0
        entry.timestamp = self._parse_timestamp(timestamp_str)
        entry.level = self._parse_level(level_str)
        entry.message = message

        # Parse additional key=value pairs
        if extra:
            entry.structured_data = self._parse_extra_fields(extra)

            # Extract container ID if present
            if "container" in entry.structured_data:
                entry.source.container_id = entry.structured_data["container"]

        entry.source.service = "dockerd"
        return entry

    def _parse_systemd(self, entry: LogEntry, match: re.Match) -> LogEntry:
        """Parse systemd journal format Docker daemon log."""
        timestamp_str, hostname, pid, message = match.groups()

        entry.format_detected = "docker_daemon_systemd"
        entry.parser_confidence = 0.9
        entry.timestamp = self._parse_timestamp(timestamp_str)
        entry.message = message
        entry.level = self._infer_level_from_message(message)
        entry.source.hostname = hostname
        entry.source.service = "dockerd"
        entry.structured_data["pid"] = pid

        return entry

    def _parse_keyvalue(self, entry: LogEntry, line: str) -> LogEntry:
        """Parse key=value style log."""
        entry.format_detected = "docker_daemon"
        entry.parser_confidence = 0.5

        # Try to extract common fields
        fields = self._parse_extra_fields(line)
        if fields:
            entry.structured_data = fields
            if "msg" in fields:
                entry.message = fields["msg"]
            elif "message" in fields:
                entry.message = fields["message"]
            else:
                entry.message = line

            if "time" in fields:
                entry.timestamp = self._parse_timestamp(fields["time"])

            if "level" in fields:
                entry.level = self._parse_level(fields["level"])
        else:
            entry.message = line
            entry.level = self._infer_level_from_message(line)

        return entry

    def _parse_extra_fields(self, extra: str) -> dict[str, Any]:
        """Parse key=value pairs from extra string."""
        fields: dict[str, Any] = {}
        # Match key=value or key="value with spaces"
        pattern = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
        for match in pattern.finditer(extra):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            fields[key] = value
        return fields

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Docker daemon logs."""
        if not sample:
            return 0.0

        matches = 0
        for line in sample:
            line = line.strip()
            if not line:
                continue
            if self.DAEMON_PATTERN.match(line):
                matches += 1
            elif self.SYSTEMD_PATTERN.match(line):
                matches += 0.8  # Slightly lower confidence for systemd format
            elif 'dockerd' in line.lower() or 'level=' in line:
                matches += 0.3

        if not sample:
            return 0.0

        return min(1.0, matches / len(sample))
