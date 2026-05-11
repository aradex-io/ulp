"""
Kubernetes log parsers.

Handles various Kubernetes log formats including:
- kubectl logs output
- Kubernetes component logs (kubelet, kube-apiserver, etc.)
- Kubernetes events
- Kubernetes audit logs
"""

import json
import re
from datetime import datetime

from ulp.core.base import BaseParser
from ulp.core.models import LogEntry, LogLevel, CorrelationIds

__all__ = [
    "KubernetesContainerParser",
    "KubernetesComponentParser",
    "KubernetesAuditParser",
    "KubernetesEventParser",
]


class KubernetesContainerParser(BaseParser):
    """
    Parse Kubernetes container logs (kubectl logs output).

    When using kubectl logs, timestamps are prefixed if --timestamps is used.
    This parser handles both with and without timestamps.

    Example logs:
        2024-01-15T10:30:00.123456789Z Starting application...
        2024-01-15T10:30:01.234567890Z {"level":"info","msg":"Ready"}
        Starting application...  (no timestamp)
    """

    name = "kubernetes_container"
    supported_formats = ["kubernetes_container", "kubectl_logs", "k8s_container"]

    # Pattern for kubectl logs with timestamp prefix
    TIMESTAMPED_PATTERN = re.compile(
        r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(.*)$'
    )

    def __init__(self):
        """Initialize the parser."""
        super().__init__()
        # For embedded JSON parsing
        from ulp.parsers.json_parser import JSONParser
        self._json_parser = JSONParser()

    def parse_line(self, line: str) -> LogEntry:
        """Parse a Kubernetes container log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        stripped = line.strip()

        # Try to extract timestamp prefix
        match = self.TIMESTAMPED_PATTERN.match(stripped)
        if match:
            timestamp_str, content = match.groups()
            entry.timestamp = self._parse_timestamp(timestamp_str)
            entry.timestamp_precision = "ns"
        else:
            content = stripped

        # Check if content is JSON
        if content.startswith("{"):
            try:
                json_entry = self._json_parser.parse_line(content)
                # Merge JSON fields into our entry
                entry.message = json_entry.message
                entry.level = json_entry.level
                entry.structured_data = json_entry.structured_data
                entry.correlation = json_entry.correlation
                if not entry.timestamp and json_entry.timestamp:
                    entry.timestamp = json_entry.timestamp
                entry.format_detected = "kubernetes_container_json"
                entry.parser_confidence = 1.0
                return entry
            except Exception:
                pass

        # Plain text log
        entry.message = content
        entry.level = self._infer_level_from_message(content)
        entry.format_detected = "kubernetes_container"
        entry.parser_confidence = 0.8 if match else 0.6

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Kubernetes container logs."""
        if not sample:
            return 0.0

        timestamped = 0
        json_logs = 0

        for line in sample:
            line = line.strip()
            if not line:
                continue
            if self.TIMESTAMPED_PATTERN.match(line):
                timestamped += 1
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    json_logs += 1
            except json.JSONDecodeError:
                pass

        # Higher confidence if we see kubectl timestamp format
        if timestamped > 0:
            return min(1.0, 0.6 + (timestamped / len(sample)) * 0.4)

        return 0.3  # Low default confidence


class KubernetesComponentParser(BaseParser):
    """
    Parse Kubernetes component logs (kubelet, kube-apiserver, etc.).

    Kubernetes components use klog format with various output styles.

    Example logs:
        I0115 10:30:00.123456   12345 server.go:123] Starting...
        E0115 10:30:01.234567   12345 handler.go:456] Error processing request
        W0115 10:30:02.345678   12345 pod.go:789] Pod not ready
    """

    name = "kubernetes_component"
    supported_formats = ["kubernetes_component", "klog", "k8s_klog"]

    # klog format: LMMDD HH:MM:SS.UUUUUU PPPP file:line] message
    # L = log level (I/W/E/F)
    KLOG_PATTERN = re.compile(
        r'^([IWEF])(\d{4})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+(\S+):(\d+)\]\s*(.*)$'
    )

    # Alternative JSON format used by newer components
    JSON_PATTERN = re.compile(r'^{.*"ts".*"msg".*}$')

    LEVEL_MAP = {
        "I": LogLevel.INFO,
        "W": LogLevel.WARNING,
        "E": LogLevel.ERROR,
        "F": LogLevel.CRITICAL,
    }

    def parse_line(self, line: str) -> LogEntry:
        """Parse a Kubernetes component log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        stripped = line.strip()

        # Try klog format
        match = self.KLOG_PATTERN.match(stripped)
        if match:
            return self._parse_klog(entry, match)

        # Try JSON format
        if stripped.startswith("{"):
            try:
                return self._parse_json(entry, stripped)
            except Exception:
                pass

        # Fallback
        entry.message = stripped
        entry.level = self._infer_level_from_message(stripped)
        entry.format_detected = "kubernetes_component"
        entry.parser_confidence = 0.3

        return entry

    def _parse_klog(self, entry: LogEntry, match: re.Match) -> LogEntry:
        """Parse klog format line."""
        level_char, mmdd, time_str, pid, filename, line_num, message = match.groups()

        entry.format_detected = "klog"
        entry.parser_confidence = 1.0
        entry.level = self.LEVEL_MAP.get(level_char, LogLevel.INFO)
        entry.message = message

        # Parse timestamp (klog uses MMDD, need to add year)
        month = int(mmdd[:2])
        day = int(mmdd[2:])
        now = datetime.now()
        year = now.year
        # Handle year rollover
        if month > now.month + 1:
            year -= 1

        try:
            ts_str = f"{year}-{month:02d}-{day:02d} {time_str}"
            entry.timestamp = self._parse_timestamp(ts_str)
            entry.timestamp_precision = "us"
        except Exception:
            pass

        # Source info
        entry.structured_data["pid"] = pid
        entry.structured_data["source_file"] = filename
        entry.structured_data["source_line"] = line_num

        return entry

    def _parse_json(self, entry: LogEntry, line: str) -> LogEntry:
        """Parse JSON format Kubernetes component log."""
        data = json.loads(line)

        entry.format_detected = "kubernetes_component_json"
        entry.parser_confidence = 1.0
        entry.structured_data = data

        # Extract common fields
        if "msg" in data:
            entry.message = data["msg"]
        elif "message" in data:
            entry.message = data["message"]
        else:
            entry.message = line

        # Timestamp
        for ts_field in ["ts", "time", "timestamp"]:
            if ts_field in data:
                ts = self._parse_timestamp(str(data[ts_field]))
                if ts:
                    entry.timestamp = ts
                    break

        # Level
        if "level" in data:
            entry.level = self._parse_level(data["level"])
        elif "severity" in data:
            entry.level = self._parse_level(data["severity"])
        else:
            entry.level = self._infer_level_from_message(entry.message)

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Kubernetes component logs."""
        if not sample:
            return 0.0

        klog_matches = 0
        json_matches = 0

        for line in sample:
            line = line.strip()
            if not line:
                continue
            if self.KLOG_PATTERN.match(line):
                klog_matches += 1
            elif self.JSON_PATTERN.match(line):
                json_matches += 1

        total = klog_matches + json_matches
        if not sample:
            return 0.0

        return total / len(sample)


class KubernetesAuditParser(BaseParser):
    """
    Parse Kubernetes audit logs.

    Audit logs are JSON objects with detailed request/response information.

    Example log:
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "level": "RequestResponse",
            "auditID": "abc-123",
            "stage": "ResponseComplete",
            "requestURI": "/api/v1/pods",
            "verb": "list",
            ...
        }
    """

    name = "kubernetes_audit"
    supported_formats = ["kubernetes_audit", "k8s_audit"]

    def parse_line(self, line: str) -> LogEntry:
        """Parse a Kubernetes audit log line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        try:
            data = json.loads(line.strip())
        except json.JSONDecodeError as e:
            entry.parse_errors.append(f"JSON decode error: {e}")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        # Verify it's an audit event
        if not isinstance(data, dict):
            entry.parse_errors.append("Not a JSON object")
            entry.message = line
            entry.parser_confidence = 0.0
            return entry

        api_version = data.get("apiVersion", "")
        if "audit.k8s.io" not in api_version:
            entry.parse_errors.append("Not a Kubernetes audit log")
            entry.message = line
            entry.parser_confidence = 0.3
            return entry

        entry.format_detected = "kubernetes_audit"
        entry.parser_confidence = 1.0
        entry.structured_data = data

        # Extract key fields
        verb = data.get("verb", "")
        uri = data.get("requestURI", "")
        entry.message = f"{verb.upper()} {uri}"

        # Timestamp
        if "stageTimestamp" in data:
            entry.timestamp = self._parse_timestamp(data["stageTimestamp"])
        elif "requestReceivedTimestamp" in data:
            entry.timestamp = self._parse_timestamp(data["requestReceivedTimestamp"])

        # Level based on response code
        response_code = data.get("responseStatus", {}).get("code", 200)

        if response_code >= 500:
            entry.level = LogLevel.ERROR
        elif response_code >= 400:
            entry.level = LogLevel.WARNING
        else:
            entry.level = LogLevel.INFO

        # Extract correlation IDs
        entry.correlation = CorrelationIds(
            request_id=data.get("auditID"),
        )

        # Extract user info
        user = data.get("user", {})
        if user:
            entry.correlation.user_id = user.get("username")
            entry.structured_data["user_groups"] = user.get("groups", [])

        # Extract source info
        source_ips = data.get("sourceIPs", [])
        if source_ips:
            entry.structured_data["source_ip"] = source_ips[0]

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Kubernetes audit logs."""
        if not sample:
            return 0.0

        matches = 0
        for line in sample:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    if "audit.k8s.io" in data.get("apiVersion", ""):
                        matches += 1
                    elif data.get("kind") == "Event" and "auditID" in data:
                        matches += 0.8
            except json.JSONDecodeError:
                pass

        if not sample:
            return 0.0

        return matches / len(sample)


class KubernetesEventParser(BaseParser):
    """
    Parse Kubernetes Event objects (kubectl get events output or JSON).

    Events describe state changes in the cluster.

    Example (kubectl output):
        LAST SEEN   TYPE      REASON     OBJECT          MESSAGE
        5m          Normal    Scheduled  pod/nginx-xxx   Successfully assigned...
        3m          Warning   Failed     pod/nginx-xxx   Error: ImagePullBackOff
    """

    name = "kubernetes_event"
    supported_formats = ["kubernetes_event", "k8s_event"]

    # Pattern for kubectl get events output
    KUBECTL_PATTERN = re.compile(
        r'^(\S+)\s+(Normal|Warning)\s+(\w+)\s+(\S+)\s+(.*)$'
    )

    LEVEL_MAP = {
        "Normal": LogLevel.INFO,
        "Warning": LogLevel.WARNING,
    }

    def parse_line(self, line: str) -> LogEntry:
        """Parse a Kubernetes event line."""
        entry = LogEntry(raw=line)
        entry.parser_name = self.name

        stripped = line.strip()

        # Skip header line
        if stripped.startswith("LAST SEEN") or stripped.startswith("NAMESPACE"):
            entry.message = stripped
            entry.level = LogLevel.UNKNOWN
            entry.parser_confidence = 0.3
            return entry

        # Try JSON format first
        if stripped.startswith("{"):
            try:
                return self._parse_json(entry, stripped)
            except Exception:
                pass

        # Try kubectl table format
        match = self.KUBECTL_PATTERN.match(stripped)
        if match:
            return self._parse_kubectl(entry, match)

        # Fallback
        entry.message = stripped
        entry.level = self._infer_level_from_message(stripped)
        entry.format_detected = "kubernetes_event"
        entry.parser_confidence = 0.3

        return entry

    def _parse_kubectl(self, entry: LogEntry, match: re.Match) -> LogEntry:
        """Parse kubectl get events table format."""
        age, event_type, reason, obj, message = match.groups()

        entry.format_detected = "kubernetes_event_table"
        entry.parser_confidence = 0.9
        entry.level = self.LEVEL_MAP.get(event_type, LogLevel.INFO)
        entry.message = f"[{reason}] {obj}: {message}"

        entry.structured_data = {
            "age": age,
            "type": event_type,
            "reason": reason,
            "object": obj,
            "message": message,
        }

        # Parse object reference
        if "/" in obj:
            kind, name = obj.split("/", 1)
            entry.structured_data["object_kind"] = kind
            entry.structured_data["object_name"] = name

        return entry

    def _parse_json(self, entry: LogEntry, line: str) -> LogEntry:
        """Parse JSON format Kubernetes event."""
        data = json.loads(line)

        entry.format_detected = "kubernetes_event_json"
        entry.parser_confidence = 1.0
        entry.structured_data = data

        # Extract key fields
        reason = data.get("reason", "")
        message = data.get("message", "")
        obj_ref = data.get("involvedObject", {})
        obj_str = f"{obj_ref.get('kind', '')}/{obj_ref.get('name', '')}"

        entry.message = f"[{reason}] {obj_str}: {message}"

        # Type -> Level
        event_type = data.get("type", "Normal")
        entry.level = self.LEVEL_MAP.get(event_type, LogLevel.INFO)

        # Timestamps
        for ts_field in ["lastTimestamp", "firstTimestamp", "eventTime"]:
            if ts_field in data and data[ts_field]:
                ts = self._parse_timestamp(data[ts_field])
                if ts:
                    entry.timestamp = ts
                    break

        # Source info
        entry.source.namespace = obj_ref.get("namespace")
        entry.source.pod_name = obj_ref.get("name") if obj_ref.get("kind") == "Pod" else None

        return entry

    def can_parse(self, sample: list[str]) -> float:
        """Determine confidence for parsing Kubernetes events."""
        if not sample:
            return 0.0

        matches = 0
        for line in sample:
            line = line.strip()
            if not line:
                continue

            # Check for table format
            if self.KUBECTL_PATTERN.match(line):
                matches += 1
            elif line.startswith("LAST SEEN"):
                matches += 0.5  # Header

            # Check for JSON format
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    if data.get("kind") == "Event" or "involvedObject" in data:
                        matches += 1
            except json.JSONDecodeError:
                pass

        if not sample:
            return 0.0

        return min(1.0, matches / len(sample))
