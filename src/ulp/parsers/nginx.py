"""
Nginx log format parsers (access and error logs).
"""

import re
from datetime import datetime

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel, HTTPInfo, NetworkInfo, CorrelationIds

__all__ = ["NginxAccessParser", "NginxErrorParser"]


class NginxAccessParser(BaseParser):
    """
    Parse Nginx default access log format.

    Default format is very similar to Apache Combined:
        $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

    Example:
        192.168.1.1 - - [27/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 612 "-" "Mozilla/5.0..."
    """

    name = "nginx_access"
    supported_formats = ["nginx_access", "nginx_default", "nginx"]

    # Pattern similar to Apache Combined but with Nginx variations
    PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'              # Client IP
        r'(?P<ident>\S+)\s+'             # Ident (usually -)
        r'(?P<user>\S+)\s+'              # Remote user
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # Timestamp in brackets
        r'"(?P<request>[^"]*)"\s+'       # Request line
        r'(?P<status>\d+)\s+'            # Status code
        r'(?P<size>\S+)'                 # Body bytes sent
        r'(?:\s+"(?P<referer>[^"]*)"\s+' # Optional referer
        r'"(?P<user_agent>[^"]*)")?'     # Optional user-agent
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single Nginx access log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        match = self.PATTERN.match(line.strip())
        if not match:
            entry.parse_errors.append("Line does not match Nginx access format")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        d = match.groupdict()

        entry.format_detected = "nginx_access"
        entry.parser_confidence = 0.95

        # Parse timestamp (same format as Apache CLF)
        entry.timestamp = self._parse_nginx_timestamp(d["timestamp"])
        if entry.timestamp:
            entry.timestamp_precision = "s"

        # Parse request line
        request_parts = self._parse_request(d["request"])

        # Build HTTPInfo
        size = d["size"]
        entry.http = HTTPInfo(
            method=request_parts.get("method"),
            path=request_parts.get("path"),
            query_string=request_parts.get("query"),
            http_version=request_parts.get("version"),
            status_code=int(d["status"]) if d["status"].isdigit() else None,
            response_size=int(size) if size and size.isdigit() else None,
        )

        # Build NetworkInfo
        referer = d.get("referer")
        user_agent = d.get("user_agent")

        entry.network = NetworkInfo(
            source_ip=d["ip"],
            referer=referer if referer and referer != "-" else None,
            user_agent=user_agent if user_agent and user_agent != "-" else None,
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
        """Determine confidence for parsing Nginx access logs."""
        if not sample:
            return 0.0

        matches = sum(1 for line in sample if self.PATTERN.match(line.strip()))
        return matches / len(sample)

    def _parse_nginx_timestamp(self, ts: str) -> datetime | None:
        """Parse Nginx timestamp format."""
        try:
            return datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                return datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None

    def _parse_request(self, request: str) -> dict[str, str | None]:
        """Parse HTTP request line."""
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
        else:
            return LogLevel.INFO


class NginxErrorParser(BaseParser):
    """
    Parse Nginx error log format.

    Format: YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message

    Example:
        2026/01/27 10:15:32 [error] 1234#5678: *9 open() "/path/file" failed (2: No such file or directory)
    """

    name = "nginx_error"
    supported_formats = ["nginx_error"]

    # Nginx error log pattern
    PATTERN = re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'  # Timestamp
        r'\[(?P<level>\w+)\]\s+'                                       # Level in brackets
        r'(?P<pid>\d+)#(?P<tid>\d+):\s*'                               # PID#TID
        r'(?:\*(?P<cid>\d+)\s+)?'                                      # Optional connection ID
        r'(?P<message>.*)'                                             # Message
    )

    # Level mapping for Nginx
    LEVEL_MAP = {
        "emerg": LogLevel.EMERGENCY,
        "alert": LogLevel.ALERT,
        "crit": LogLevel.CRITICAL,
        "error": LogLevel.ERROR,
        "warn": LogLevel.WARNING,
        "notice": LogLevel.NOTICE,
        "info": LogLevel.INFO,
        "debug": LogLevel.DEBUG,
    }

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single Nginx error log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        match = self.PATTERN.match(line.strip())
        if not match:
            entry.parse_errors.append("Line does not match Nginx error format")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        d = match.groupdict()

        entry.format_detected = "nginx_error"
        entry.parser_confidence = 0.95

        # Parse timestamp
        entry.timestamp = self._parse_error_timestamp(d["timestamp"])
        if entry.timestamp:
            entry.timestamp_precision = "s"

        # Parse level
        level_str = d["level"].lower()
        entry.level = self.LEVEL_MAP.get(level_str, LogLevel.UNKNOWN)

        # Set message
        entry.message = d["message"]

        # Store extra info
        entry.extra = {
            "pid": int(d["pid"]),
            "tid": int(d["tid"]),
        }
        if d.get("cid"):
            entry.extra["connection_id"] = int(d["cid"])

        # Set source service
        entry.source.service = "nginx"

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Nginx error logs."""
        if not sample:
            return 0.0

        matches = sum(1 for line in sample if self.PATTERN.match(line.strip()))
        return matches / len(sample)

    def _parse_error_timestamp(self, ts: str) -> datetime | None:
        """Parse Nginx error timestamp format."""
        try:
            return datetime.strptime(ts, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
