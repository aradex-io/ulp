"""
Apache log format parsers (Common Log Format and Combined Log Format).
"""

import re
from datetime import datetime

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel, HTTPInfo, NetworkInfo, CorrelationIds

__all__ = ["ApacheCommonParser", "ApacheCombinedParser"]


class ApacheCommonParser(BaseParser):
    """
    Parse Apache Common Log Format (CLF).

    Format: host ident authuser [date] "request" status bytes

    Example:
        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    """

    name = "apache_common"
    supported_formats = ["apache_common", "clf"]

    # Pattern for Common Log Format
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'            # Client IP
        r'(?P<ident>\S+)\s+'           # Ident (usually -)
        r'(?P<user>\S+)\s+'            # Auth user (usually -)
        r'\[(?P<timestamp>[^\]]+)\]\s+' # Timestamp in brackets
        r'"(?P<request>[^"]*)"\s+'     # Request line in quotes
        r'(?P<status>\d+)\s+'          # Status code
        r'(?P<size>\S+)'               # Response size (or -)
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single Apache Common Log Format line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        match = self.PATTERN.match(line.strip())
        if not match:
            entry.parse_errors.append("Line does not match Apache Common format")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        d = match.groupdict()

        entry.format_detected = "apache_common"
        entry.parser_confidence = 0.95

        # Parse timestamp
        entry.timestamp = self._parse_clf_timestamp(d["timestamp"])
        if entry.timestamp:
            entry.timestamp_precision = "s"

        # Parse request line
        request_parts = self._parse_request(d["request"])

        # Build HTTPInfo
        entry.http = HTTPInfo(
            method=request_parts.get("method"),
            path=request_parts.get("path"),
            query_string=request_parts.get("query"),
            http_version=request_parts.get("version"),
            status_code=int(d["status"]) if d["status"].isdigit() else None,
            response_size=int(d["size"]) if d["size"].isdigit() else None,
        )

        # Build NetworkInfo
        entry.network = NetworkInfo(source_ip=d["ip"])

        # Determine level from status code
        entry.level = self._level_from_status(entry.http.status_code)

        # Build message
        entry.message = f"{request_parts.get('method', '-')} {request_parts.get('path', '-')} -> {d['status']}"

        # Extract user if authenticated
        if d["user"] != "-":
            entry.correlation = CorrelationIds(user_id=d["user"])

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Apache Common logs."""
        if not sample:
            return 0.0

        matches = sum(1 for line in sample if self.PATTERN.match(line.strip()))
        return matches / len(sample)

    def _parse_clf_timestamp(self, ts: str) -> datetime | None:
        """
        Parse Common Log Format timestamp.

        Format: 10/Oct/2000:13:55:36 -0700
        """
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                # Without timezone
                return datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None

    def _parse_request(self, request: str) -> dict[str, str | None]:
        """
        Parse HTTP request line.

        Example: "GET /path?query=value HTTP/1.1"
        """
        parts = request.split()
        result: dict[str, str | None] = {
            "method": None,
            "path": None,
            "query": None,
            "version": None,
        }

        if len(parts) >= 1:
            result["method"] = parts[0]

        if len(parts) >= 2:
            path_query = parts[1]
            if "?" in path_query:
                path, query = path_query.split("?", 1)
                result["path"] = path
                result["query"] = query
            else:
                result["path"] = path_query

        if len(parts) >= 3:
            result["version"] = parts[2]

        return result

    def _level_from_status(self, status: int | None) -> LogLevel:
        """Determine log level from HTTP status code."""
        if status is None:
            return LogLevel.UNKNOWN

        if status >= 500:
            return LogLevel.ERROR
        elif status >= 400:
            return LogLevel.WARNING
        elif status >= 300:
            return LogLevel.INFO
        else:
            return LogLevel.INFO


class ApacheCombinedParser(ApacheCommonParser):
    """
    Parse Apache Combined Log Format.

    Format: host ident authuser [date] "request" status bytes "referer" "user_agent"

    Example:
        127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/5.0..."
    """

    name = "apache_combined"
    supported_formats = ["apache_combined", "combined"]

    # Pattern for Combined Log Format
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'            # Client IP
        r'(?P<ident>\S+)\s+'           # Ident (usually -)
        r'(?P<user>\S+)\s+'            # Auth user (usually -)
        r'\[(?P<timestamp>[^\]]+)\]\s+' # Timestamp in brackets
        r'"(?P<request>[^"]*)"\s+'     # Request line in quotes
        r'(?P<status>\d+)\s+'          # Status code
        r'(?P<size>\S+)\s+'            # Response size (or -)
        r'"(?P<referer>[^"]*)"\s+'     # Referer in quotes
        r'"(?P<user_agent>[^"]*)"'     # User-Agent in quotes
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single Apache Combined Log Format line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        match = self.PATTERN.match(line.strip())
        if not match:
            # Fall back to Common format
            return super().parse_line(line)

        d = match.groupdict()

        entry.format_detected = "apache_combined"
        entry.parser_confidence = 0.98

        # Parse timestamp
        entry.timestamp = self._parse_clf_timestamp(d["timestamp"])
        if entry.timestamp:
            entry.timestamp_precision = "s"

        # Parse request line
        request_parts = self._parse_request(d["request"])

        # Build HTTPInfo
        entry.http = HTTPInfo(
            method=request_parts.get("method"),
            path=request_parts.get("path"),
            query_string=request_parts.get("query"),
            http_version=request_parts.get("version"),
            status_code=int(d["status"]) if d["status"].isdigit() else None,
            response_size=int(d["size"]) if d["size"].isdigit() else None,
        )

        # Build NetworkInfo with referer and user_agent
        referer = d["referer"] if d["referer"] != "-" else None
        user_agent = d["user_agent"] if d["user_agent"] != "-" else None

        entry.network = NetworkInfo(
            source_ip=d["ip"],
            referer=referer,
            user_agent=user_agent,
        )

        # Determine level from status code
        entry.level = self._level_from_status(entry.http.status_code)

        # Build message
        entry.message = f"{request_parts.get('method', '-')} {request_parts.get('path', '-')} -> {d['status']}"

        # Extract user if authenticated
        if d["user"] != "-":
            entry.correlation = CorrelationIds(user_id=d["user"])

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Apache Combined logs."""
        if not sample:
            return 0.0

        combined_matches = sum(1 for line in sample if self.PATTERN.match(line.strip()))

        # If Combined matches, return high confidence
        if combined_matches > 0:
            return (combined_matches / len(sample)) * 1.1  # Slight boost over Common

        # Fall back to Common format matching
        return super().can_parse(sample) * 0.9
