"""
Built-in format signatures for log format detection.
"""

from ulp.core.models import FormatSignature

__all__ = ["BUILTIN_SIGNATURES"]


BUILTIN_SIGNATURES = [
    # JSON structured logs
    FormatSignature(
        name="json_structured",
        description="JSON-formatted structured logs (JSONL/NDJSON)",
        magic_patterns=[
            r'^\s*\{.*"(timestamp|time|@timestamp|ts|datetime|created|level|severity|msg|message)"',
        ],
        line_patterns=[
            r'^\s*\{.*\}\s*$',
        ],
        is_json=True,
        weight=1.5,  # High weight because JSON is unambiguous
        parser_class="ulp.parsers.json_parser.JSONParser",
    ),

    # Apache Combined Log Format (more specific, check first)
    FormatSignature(
        name="apache_combined",
        description="Apache Combined Log Format",
        magic_patterns=[
            r'^\S+\s+\S+\s+\S+\s+\[[\d]{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"[A-Z]+\s+\S+.*"\s+\d{3}\s+\d+\s+"[^"]*"\s+"[^"]*"',
        ],
        line_patterns=[
            r'\[[\d]{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]',
            r'"[A-Z]+ .+ HTTP/[\d.]+"',
        ],
        weight=1.3,
        parser_class="ulp.parsers.apache.ApacheCombinedParser",
    ),

    # Apache Common Log Format
    FormatSignature(
        name="apache_common",
        description="Apache Common Log Format (CLF)",
        magic_patterns=[
            r'^\S+\s+\S+\s+\S+\s+\[[\d]{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"[A-Z]+\s+\S+.*"\s+\d{3}\s+\d+$',
        ],
        line_patterns=[
            r'\[[\d]{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
        ],
        weight=1.2,
        parser_class="ulp.parsers.apache.ApacheCommonParser",
    ),

    # Nginx access log (default format similar to Apache combined)
    FormatSignature(
        name="nginx_access",
        description="Nginx default access log format",
        magic_patterns=[
            r'^\S+\s+-\s+\S+\s+\[[\d]{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"[A-Z]+',
        ],
        line_patterns=[
            r'\[[\d]{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
            r'"[A-Z]+ .+ HTTP/[\d.]+"',
        ],
        weight=1.2,
        parser_class="ulp.parsers.nginx.NginxAccessParser",
    ),

    # Nginx error log
    FormatSignature(
        name="nginx_error",
        description="Nginx error log format",
        magic_patterns=[
            r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[(emerg|alert|crit|error|warn|notice|info|debug)\]',
        ],
        line_patterns=[
            r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}',
            r'\[(emerg|alert|crit|error|warn|notice|info|debug)\]',
        ],
        weight=1.3,
        parser_class="ulp.parsers.nginx.NginxErrorParser",
    ),

    # Syslog RFC 5424 (modern format, check first)
    FormatSignature(
        name="syslog_rfc5424",
        description="Syslog RFC 5424 format",
        magic_patterns=[
            r'^<\d{1,3}>1\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
        ],
        line_patterns=[
            r'^<\d{1,3}>1\s+',
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?',
        ],
        weight=1.4,
        parser_class="ulp.parsers.syslog.SyslogRFC5424Parser",
    ),

    # Syslog RFC 3164 (BSD format)
    FormatSignature(
        name="syslog_rfc3164",
        description="Syslog RFC 3164 (BSD) format",
        magic_patterns=[
            r'^<\d{1,3}>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        ],
        line_patterns=[
            # Match with or without priority
            r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+',
            r'^<\d{1,3}>',
        ],
        weight=1.2,
        parser_class="ulp.parsers.syslog.SyslogRFC3164Parser",
    ),

    # Python logging default format
    FormatSignature(
        name="python_logging",
        description="Python logging default format",
        magic_patterns=[
            r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+-\s+\S+\s+-\s+(DEBUG|INFO|WARNING|ERROR|CRITICAL)',
            r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}\s+\S+\s+(DEBUG|INFO|WARNING|ERROR|CRITICAL)',
        ],
        line_patterns=[
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3}',
            r'(DEBUG|INFO|WARNING|ERROR|CRITICAL)',
        ],
        weight=1.3,
        parser_class="ulp.parsers.python_logging.PythonLoggingParser",
    ),

    # Generic/fallback (lowest priority)
    FormatSignature(
        name="generic",
        description="Generic log format (fallback)",
        magic_patterns=[],
        line_patterns=[
            r'^\d{4}[-/]\d{2}[-/]\d{2}',  # Date at start
            r'\d{2}:\d{2}:\d{2}',  # Time anywhere
        ],
        weight=0.5,
        parser_class="ulp.parsers.generic.GenericParser",
    ),
]
