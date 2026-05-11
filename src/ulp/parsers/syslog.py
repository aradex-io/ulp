"""
Syslog parsers for RFC 3164 (BSD) and RFC 5424 formats.
"""

import re
from datetime import datetime

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel, LogSource

__all__ = ["SyslogRFC3164Parser", "SyslogRFC5424Parser"]


# Syslog severity to LogLevel mapping (RFC 5424)
SYSLOG_SEVERITY = {
    0: LogLevel.EMERGENCY,   # Emergency
    1: LogLevel.ALERT,       # Alert
    2: LogLevel.CRITICAL,    # Critical
    3: LogLevel.ERROR,       # Error
    4: LogLevel.WARNING,     # Warning
    5: LogLevel.NOTICE,      # Notice
    6: LogLevel.INFO,        # Informational
    7: LogLevel.DEBUG,       # Debug
}


class SyslogRFC3164Parser(BaseParser):
    """
    Parse RFC 3164 (BSD) syslog format.

    Format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    Or without PRI: TIMESTAMP HOSTNAME TAG: MESSAGE

    Examples:
        <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick
        Jan 27 10:15:32 server sshd[1234]: Accepted publickey for user
    """

    name = "syslog_rfc3164"
    supported_formats = ["syslog_rfc3164", "syslog_bsd", "syslog"]

    # Pattern with optional priority
    PATTERN = re.compile(
        r'^(?:<(?P<pri>\d{1,3})>)?'            # Optional priority
        r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # BSD timestamp
        r'(?P<hostname>\S+)\s+'                 # Hostname
        r'(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*'  # Tag with optional PID
        r'(?P<message>.*)'                      # Message
    )

    # Alternate pattern for slightly different formats
    PATTERN_ALT = re.compile(
        r'^(?:<(?P<pri>\d{1,3})>)?'
        r'(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<message>.*)'
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single RFC 3164 syslog line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        match = self.PATTERN.match(line.strip())
        if not match:
            match = self.PATTERN_ALT.match(line.strip())
            if not match:
                entry.parse_errors.append("Line does not match RFC 3164 format")
                entry.message = line
                entry.parser_confidence = 0.0
                return entry

        d = match.groupdict()

        entry.format_detected = "syslog_rfc3164"
        entry.parser_confidence = 0.90

        # Parse priority if present
        if d.get("pri"):
            pri = int(d["pri"])
            facility = pri >> 3
            severity = pri & 0x07
            entry.level = SYSLOG_SEVERITY.get(severity, LogLevel.UNKNOWN)
            entry.extra["facility"] = facility
            entry.extra["severity"] = severity
        else:
            entry.level = self._infer_level_from_message(d["message"])

        # Parse timestamp (add current year since BSD format doesn't include it)
        entry.timestamp = self._parse_bsd_timestamp(d["timestamp"])
        if entry.timestamp:
            entry.timestamp_precision = "s"

        # Set source info
        entry.source = LogSource(
            hostname=d["hostname"],
            service=d.get("tag"),
        )

        # Store PID if present
        if d.get("pid"):
            entry.extra["pid"] = int(d["pid"])

        # Set message
        entry.message = d["message"]

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing RFC 3164 logs."""
        if not sample:
            return 0.0

        matches = 0
        for line in sample:
            line = line.strip()
            if self.PATTERN.match(line) or self.PATTERN_ALT.match(line):
                matches += 1

        return matches / len(sample)

    def _parse_bsd_timestamp(self, ts: str) -> datetime | None:
        """
        Parse BSD syslog timestamp.

        Format: "Oct 11 22:14:15" (no year)
        """
        try:
            # Add current year
            current_year = datetime.now().year
            ts_with_year = f"{ts} {current_year}"
            return datetime.strptime(ts_with_year, "%b %d %H:%M:%S %Y")
        except ValueError:
            return None


class SyslogRFC5424Parser(BaseParser):
    """
    Parse RFC 5424 syslog format.

    Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG

    Examples:
        <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed
        <165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.
    """

    name = "syslog_rfc5424"
    supported_formats = ["syslog_rfc5424"]

    # RFC 5424 pattern
    PATTERN = re.compile(
        r'^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+'           # Priority and version
        r'(?P<timestamp>\S+)\s+'                            # ISO timestamp or NILVALUE
        r'(?P<hostname>\S+)\s+'                             # Hostname
        r'(?P<appname>\S+)\s+'                              # App name
        r'(?P<procid>\S+)\s+'                               # Process ID
        r'(?P<msgid>\S+)\s+'                                # Message ID
        r'(?P<sd>-|\[.*?\](?:\s*\[.*?\])*)\s*'             # Structured data
        r'(?P<message>.*)?'                                 # Message (optional)
    )

    def parse_line(self, line: str) -> LogEntry:
        """Parse a single RFC 5424 syslog line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        match = self.PATTERN.match(line.strip())
        if not match:
            entry.parse_errors.append("Line does not match RFC 5424 format")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        d = match.groupdict()

        entry.format_detected = "syslog_rfc5424"
        entry.parser_confidence = 0.95

        # Parse priority
        pri = int(d["pri"])
        facility = pri >> 3
        severity = pri & 0x07
        entry.level = SYSLOG_SEVERITY.get(severity, LogLevel.UNKNOWN)
        entry.extra["facility"] = facility
        entry.extra["severity"] = severity

        # Parse timestamp
        ts = d["timestamp"]
        if ts != "-":
            entry.timestamp = self._parse_timestamp(ts)
            if entry.timestamp:
                entry.timestamp_precision = self._detect_precision(ts)

        # Set source info
        hostname = d["hostname"] if d["hostname"] != "-" else None
        appname = d["appname"] if d["appname"] != "-" else None
        entry.source = LogSource(
            hostname=hostname,
            service=appname,
        )

        # Store process ID and message ID
        if d["procid"] != "-":
            entry.extra["procid"] = d["procid"]
        if d["msgid"] != "-":
            entry.extra["msgid"] = d["msgid"]

        # Parse structured data
        if d["sd"] != "-":
            entry.structured_data = self._parse_structured_data(d["sd"])

        # Set message
        entry.message = d["message"] or ""

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing RFC 5424 logs."""
        if not sample:
            return 0.0

        matches = sum(1 for line in sample if self.PATTERN.match(line.strip()))
        return matches / len(sample)

    def _detect_precision(self, ts: str) -> str:
        """Detect timestamp precision."""
        if "." in ts:
            # Count decimal places after the dot
            parts = ts.split(".")
            if len(parts) > 1:
                decimal = parts[1].rstrip("Z").rstrip("+-0123456789:")
                if len(decimal) >= 6:
                    return "us"
                elif len(decimal) >= 3:
                    return "ms"
        return "s"

    def _parse_structured_data(self, sd: str) -> dict:
        """
        Parse RFC 5424 structured data.

        Format: [sdid param="value" param2="value2"][sdid2 ...]
        """
        result = {}

        # Find all SD-ELEMENT blocks
        sd_pattern = re.compile(r'\[([^\]]+)\]')
        for match in sd_pattern.finditer(sd):
            block = match.group(1)
            parts = block.split(None, 1)

            if len(parts) >= 1:
                sd_id = parts[0]
                params = {}

                if len(parts) > 1:
                    # Parse parameters
                    param_pattern = re.compile(r'(\S+)="([^"]*)"')
                    for param_match in param_pattern.finditer(parts[1]):
                        params[param_match.group(1)] = param_match.group(2)

                result[sd_id] = params

        return result
