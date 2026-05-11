"""
Security configuration and utilities for ULP.

Centralizes all security-related constants, validators, and helpers
to ensure consistent security enforcement across the codebase.
"""

import os
import re
import warnings
from pathlib import Path
from typing import Any

from ulp.core.exceptions import ULPError

__all__ = [
    # Configuration constants
    "MAX_LINE_LENGTH",
    "MAX_ORPHAN_ENTRIES",
    "MAX_SESSION_GROUPS",
    "MAX_JSON_DEPTH",
    "REGEX_TIMEOUT_SECONDS",
    "CSV_FORMULA_PREFIXES",
    # Exceptions
    "LineTooLongError",
    "SecurityValidationError",
    # Validators
    "validate_line_length",
    "validate_json_depth",
    "validate_regex_pattern",
    "sanitize_csv_cell",
    "check_symlink",
]


# =============================================================================
# Security Configuration Constants
# =============================================================================

# H1: Maximum line length (10MB as requested)
MAX_LINE_LENGTH = 10 * 1024 * 1024  # 10MB

# H2: Maximum orphan entries in correlation (entries without correlation IDs)
MAX_ORPHAN_ENTRIES = 10_000

# H3: Maximum session groups to track simultaneously
MAX_SESSION_GROUPS = 100_000

# H4: Maximum JSON nesting depth
MAX_JSON_DEPTH = 50

# M1/M2: Regex matching timeout (seconds) - used as guidance for complex patterns
REGEX_TIMEOUT_SECONDS = 5.0

# M4: Characters that trigger formula execution in spreadsheets
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


# =============================================================================
# Security Exceptions
# =============================================================================

class SecurityValidationError(ULPError):
    """Raised when security validation fails."""

    def __init__(self, message: str, validation_type: str, details: dict | None = None):
        super().__init__(message, details)
        self.validation_type = validation_type


class LineTooLongError(SecurityValidationError):
    """
    Raised when a log line exceeds MAX_LINE_LENGTH.

    The error message suggests splitting the file if needed.
    """

    def __init__(self, line_length: int, max_length: int = MAX_LINE_LENGTH):
        message = (
            f"Line length ({line_length:,} bytes) exceeds maximum allowed "
            f"({max_length:,} bytes). If this is a valid log file with very "
            f"long lines, consider splitting lines or preprocessing the file "
            f"before parsing."
        )
        super().__init__(
            message,
            validation_type="line_length",
            details={
                "line_length": line_length,
                "max_length": max_length,
            }
        )


# =============================================================================
# Validation Functions
# =============================================================================

def validate_line_length(line: str, max_length: int = MAX_LINE_LENGTH) -> str:
    """
    Validate that a line does not exceed the maximum allowed length.

    Args:
        line: The line to validate
        max_length: Maximum allowed length in bytes

    Returns:
        The original line if valid

    Raises:
        LineTooLongError: If line exceeds max_length
    """
    line_length = len(line.encode("utf-8", errors="replace"))
    if line_length > max_length:
        raise LineTooLongError(line_length, max_length)
    return line


def validate_json_depth(data: Any, max_depth: int = MAX_JSON_DEPTH, current_depth: int = 0) -> bool:
    """
    Check if JSON data exceeds maximum nesting depth.

    Args:
        data: Parsed JSON data to check
        max_depth: Maximum allowed nesting depth
        current_depth: Current depth (used internally for recursion)

    Returns:
        True if depth is within limits

    Raises:
        SecurityValidationError: If depth exceeds max_depth
    """
    if current_depth > max_depth:
        raise SecurityValidationError(
            f"JSON nesting depth ({current_depth}) exceeds maximum ({max_depth})",
            validation_type="json_depth",
            details={"depth": current_depth, "max_depth": max_depth},
        )

    if isinstance(data, dict):
        for value in data.values():
            validate_json_depth(value, max_depth, current_depth + 1)
    elif isinstance(data, list):
        for item in data:
            validate_json_depth(item, max_depth, current_depth + 1)

    return True


def validate_regex_pattern(pattern: str, max_length: int = 1000) -> re.Pattern:
    """
    Validate and compile a regex pattern safely.

    Checks for:
    - Pattern length limits
    - Valid regex syntax
    - Known problematic patterns (basic ReDoS detection)

    Args:
        pattern: Regex pattern string
        max_length: Maximum pattern length

    Returns:
        Compiled regex pattern

    Raises:
        SecurityValidationError: If pattern is invalid or potentially dangerous
    """
    # Check pattern length
    if len(pattern) > max_length:
        raise SecurityValidationError(
            f"Regex pattern too long ({len(pattern)} > {max_length})",
            validation_type="regex_length",
        )

    # Basic ReDoS pattern detection - look for nested quantifiers
    # This is a heuristic, not comprehensive
    dangerous_patterns = [
        r"\(\?.*\+.*\+",  # Nested + quantifiers in group
        r"\(\?.*\*.*\*",  # Nested * quantifiers in group
        r"\([^)]*\+\)[^)]*\+",  # (a+)+ pattern
        r"\([^)]*\*\)[^)]*\*",  # (a*)* pattern
    ]

    for dangerous in dangerous_patterns:
        if re.search(dangerous, pattern):
            raise SecurityValidationError(
                "Regex pattern contains potentially dangerous nested quantifiers. "
                "Please simplify the pattern.",
                validation_type="regex_redos",
                details={"pattern_preview": pattern[:100]},
            )

    # Try to compile
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise SecurityValidationError(
            f"Invalid regex pattern: {e}",
            validation_type="regex_syntax",
            details={"error": str(e)},
        )


def sanitize_csv_cell(value: str) -> str:
    """
    Sanitize a cell value for CSV output to prevent formula injection.

    Spreadsheet applications (Excel, LibreOffice Calc, Google Sheets)
    can execute formulas starting with =, +, -, @, tab, or carriage return.

    Args:
        value: The cell value to sanitize

    Returns:
        Sanitized value safe for CSV output
    """
    if value and value[0] in CSV_FORMULA_PREFIXES:
        # Prefix with single quote to prevent formula execution
        return "'" + value
    return value


def check_symlink(path: Path | str, warn: bool = True) -> tuple[bool, Path]:
    """
    Check if a path is a symlink and optionally warn.

    Args:
        path: Path to check
        warn: If True, emit a warning when symlink is detected

    Returns:
        Tuple of (is_symlink, resolved_path)
    """
    path = Path(path)
    is_symlink = path.is_symlink()

    if is_symlink and warn:
        resolved = path.resolve()
        warnings.warn(
            f"Following symlink: {path} -> {resolved}",
            UserWarning,
            stacklevel=2,
        )

    return is_symlink, path.resolve()
