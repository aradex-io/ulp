"""
Normalization step implementations.

Provides common normalization operations for log entries.
"""

import re
from datetime import timezone
from typing import Any

from ulp.domain.entities import LogEntry, LogLevel
from ulp.domain.services import NormalizationStep

__all__ = [
    "TimestampNormalizer",
    "LevelNormalizer",
    "FieldNormalizer",
    "HostnameEnricher",
    "GeoIPEnricher",
]


class TimestampNormalizer(NormalizationStep):
    """
    Normalize timestamps to a consistent timezone.

    Converts all timestamps to a target timezone (default: UTC).

    Example:
        normalizer = TimestampNormalizer(target_tz="UTC")
        entry = normalizer.normalize(entry)
        # entry.timestamp is now in UTC
    """

    def __init__(self, target_tz: str = "UTC"):
        """
        Initialize timestamp normalizer.

        Args:
            target_tz: Target timezone name (only "UTC" supported without pytz)
        """
        self.target_tz = target_tz
        if target_tz == "UTC":
            self._tz = timezone.utc
        else:
            # For non-UTC, would need pytz or zoneinfo (Python 3.9+)
            try:
                from zoneinfo import ZoneInfo
                self._tz = ZoneInfo(target_tz)
            except ImportError:
                # Fallback to UTC
                self._tz = timezone.utc

    @property
    def name(self) -> str:
        return "timestamp_normalizer"

    def normalize(self, entry: LogEntry) -> LogEntry:
        """Convert timestamp to target timezone."""
        if entry.timestamp is None:
            return entry

        # If timestamp is naive, assume UTC
        if entry.timestamp.tzinfo is None:
            entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)

        # Convert to target timezone
        entry.timestamp = entry.timestamp.astimezone(self._tz)
        return entry


class LevelNormalizer(NormalizationStep):
    """
    Normalize log levels to standard values.

    Maps various level representations to LogLevel enum.

    Example:
        normalizer = LevelNormalizer()
        # "WARN" -> LogLevel.WARNING
        # "err" -> LogLevel.ERROR
        # "Information" -> LogLevel.INFO
    """

    # Common level aliases
    LEVEL_ALIASES: dict[str, LogLevel] = {
        # Standard
        "debug": LogLevel.DEBUG,
        "info": LogLevel.INFO,
        "information": LogLevel.INFO,
        "informational": LogLevel.INFO,
        "notice": LogLevel.INFO,
        "warn": LogLevel.WARNING,
        "warning": LogLevel.WARNING,
        "error": LogLevel.ERROR,
        "err": LogLevel.ERROR,
        "critical": LogLevel.CRITICAL,
        "crit": LogLevel.CRITICAL,
        "fatal": LogLevel.CRITICAL,
        "emergency": LogLevel.CRITICAL,
        "emerg": LogLevel.CRITICAL,
        "alert": LogLevel.CRITICAL,
        "panic": LogLevel.CRITICAL,
        "trace": LogLevel.TRACE,
        "verbose": LogLevel.TRACE,
        # Syslog numeric levels
        "0": LogLevel.CRITICAL,  # emergency
        "1": LogLevel.CRITICAL,  # alert
        "2": LogLevel.CRITICAL,  # critical
        "3": LogLevel.ERROR,     # error
        "4": LogLevel.WARNING,   # warning
        "5": LogLevel.INFO,      # notice
        "6": LogLevel.INFO,      # info
        "7": LogLevel.DEBUG,     # debug
    }

    @property
    def name(self) -> str:
        return "level_normalizer"

    def normalize(self, entry: LogEntry) -> LogEntry:
        """Normalize log level."""
        if entry.level != LogLevel.UNKNOWN:
            return entry

        # Try to extract level from structured data
        level_value = None
        for field in ["level", "severity", "loglevel", "log_level", "priority"]:
            if field in entry.structured_data:
                level_value = str(entry.structured_data[field]).lower()
                break

        if level_value and level_value in self.LEVEL_ALIASES:
            entry.level = self.LEVEL_ALIASES[level_value]

        return entry


class FieldNormalizer(NormalizationStep):
    """
    Normalize field names to a standard schema.

    Maps various field name variations to canonical names.

    Example:
        mappings = {
            "canonical_name": ["alias1", "alias2", "alias3"],
            "timestamp": ["@timestamp", "time", "datetime", "ts"],
            "message": ["msg", "log", "text"],
        }
        normalizer = FieldNormalizer(mappings)
    """

    # Default field mappings
    DEFAULT_MAPPINGS: dict[str, list[str]] = {
        "timestamp": ["@timestamp", "time", "datetime", "ts", "date", "event_time"],
        "message": ["msg", "log", "text", "body", "content"],
        "level": ["severity", "loglevel", "log_level", "priority", "lvl"],
        "logger": ["logger_name", "name", "component", "module"],
        "thread": ["thread_name", "thread_id", "tid"],
        "host": ["hostname", "host_name", "server", "node"],
        "service": ["service_name", "app", "application", "app_name"],
        "request_id": ["requestId", "request-id", "x-request-id", "correlation_id"],
        "trace_id": ["traceId", "trace-id", "x-trace-id"],
        "user_id": ["userId", "user-id", "uid", "user"],
        "ip": ["client_ip", "clientip", "remote_addr", "source_ip", "src_ip"],
        "method": ["http_method", "request_method", "verb"],
        "path": ["url", "uri", "request_path", "endpoint"],
        "status": ["status_code", "http_status", "response_code", "code"],
        "duration": ["response_time", "latency", "elapsed", "took", "duration_ms"],
    }

    def __init__(
        self,
        field_mappings: dict[str, list[str]] | None = None,
        preserve_original: bool = True
    ):
        """
        Initialize field normalizer.

        Args:
            field_mappings: Custom field mappings (merged with defaults)
            preserve_original: Keep original field alongside normalized
        """
        self.mappings = dict(self.DEFAULT_MAPPINGS)
        if field_mappings:
            self.mappings.update(field_mappings)

        # Build reverse lookup
        self._reverse_map: dict[str, str] = {}
        for canonical, aliases in self.mappings.items():
            for alias in aliases:
                self._reverse_map[alias.lower()] = canonical

        self.preserve_original = preserve_original

    @property
    def name(self) -> str:
        return "field_normalizer"

    def normalize(self, entry: LogEntry) -> LogEntry:
        """Normalize field names in structured data."""
        if not entry.structured_data:
            return entry

        normalized: dict[str, Any] = {}
        for key, value in entry.structured_data.items():
            canonical = self._reverse_map.get(key.lower())
            if canonical:
                normalized[canonical] = value
                if self.preserve_original and key != canonical:
                    normalized[f"_original_{key}"] = value
            else:
                normalized[key] = value

        entry.structured_data = normalized
        return entry


class HostnameEnricher(NormalizationStep):
    """
    Enrich entries with hostname resolution.

    Resolves IP addresses to hostnames (with caching).

    Example:
        enricher = HostnameEnricher(cache_size=1000)
        # entry with ip="192.168.1.1" gets hostname="server.local"
    """

    def __init__(
        self,
        ip_fields: list[str] | None = None,
        cache_size: int = 1000,
        timeout: float = 0.5
    ):
        """
        Initialize hostname enricher.

        Args:
            ip_fields: Fields containing IP addresses to resolve
            cache_size: Number of resolutions to cache
            timeout: DNS lookup timeout in seconds
        """
        self.ip_fields = ip_fields or ["ip", "client_ip", "source_ip", "remote_addr"]
        self.cache_size = cache_size
        self.timeout = timeout
        self._cache: dict[str, str | None] = {}

    @property
    def name(self) -> str:
        return "hostname_enricher"

    def normalize(self, entry: LogEntry) -> LogEntry:
        """Enrich entry with hostname."""
        for field in self.ip_fields:
            if field in entry.structured_data:
                ip = entry.structured_data[field]
                if ip and isinstance(ip, str):
                    hostname = self._resolve(ip)
                    if hostname:
                        entry.structured_data[f"{field}_hostname"] = hostname
                    break
        return entry

    def _resolve(self, ip: str) -> str | None:
        """Resolve IP to hostname with caching."""
        if ip in self._cache:
            return self._cache[ip]

        # Basic IP validation
        if not self._is_valid_ip(ip):
            return None

        hostname = None
        try:
            import socket
            socket.setdefaulttimeout(self.timeout)
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            pass

        # Cache result (including None for failed lookups)
        if len(self._cache) >= self.cache_size:
            # Simple cache eviction: clear oldest half
            keys = list(self._cache.keys())
            for k in keys[:len(keys)//2]:
                del self._cache[k]

        self._cache[ip] = hostname
        return hostname

    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation."""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        # IPv6 would need more complex validation
        return ':' in ip  # Basic IPv6 check


class GeoIPEnricher(NormalizationStep):
    """
    Enrich entries with geographic information from IP addresses.

    Requires maxminddb or geoip2 library and GeoLite2 database.

    Example:
        enricher = GeoIPEnricher("/path/to/GeoLite2-City.mmdb")
        # entry with ip="8.8.8.8" gets country="US", city="Mountain View"
    """

    def __init__(
        self,
        database_path: str | None = None,
        ip_fields: list[str] | None = None
    ):
        """
        Initialize GeoIP enricher.

        Args:
            database_path: Path to MaxMind GeoIP database
            ip_fields: Fields containing IP addresses
        """
        self.database_path = database_path
        self.ip_fields = ip_fields or ["ip", "client_ip", "source_ip"]
        self._reader = None
        self._available = False

        # Try to initialize if database provided
        if database_path:
            self._init_reader()

    def _init_reader(self) -> None:
        """Initialize the GeoIP reader."""
        if not self.database_path:
            return

        try:
            import maxminddb
            self._reader = maxminddb.open_database(self.database_path)
            self._available = True
        except ImportError:
            # Try geoip2 as fallback
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(self.database_path)
                self._available = True
            except ImportError:
                pass
        except Exception:
            pass

    @property
    def name(self) -> str:
        return "geoip_enricher"

    def normalize(self, entry: LogEntry) -> LogEntry:
        """Enrich entry with GeoIP data."""
        if not self._available:
            return entry

        for field in self.ip_fields:
            if field in entry.structured_data:
                ip = entry.structured_data[field]
                if ip and isinstance(ip, str):
                    geo_data = self._lookup(ip)
                    if geo_data:
                        entry.structured_data["geo"] = geo_data
                    break
        return entry

    def _lookup(self, ip: str) -> dict[str, Any] | None:
        """Look up GeoIP data for an IP address."""
        if not self._reader:
            return None

        try:
            result = self._reader.get(ip)
            if result:
                return {
                    "country": result.get("country", {}).get("iso_code"),
                    "country_name": result.get("country", {}).get("names", {}).get("en"),
                    "city": result.get("city", {}).get("names", {}).get("en"),
                    "latitude": result.get("location", {}).get("latitude"),
                    "longitude": result.get("location", {}).get("longitude"),
                }
        except Exception:
            pass
        return None

    def __del__(self):
        """Clean up reader."""
        if self._reader and hasattr(self._reader, 'close'):
            try:
                self._reader.close()
            except Exception:
                pass
