"""
Custom exceptions for ULP.
"""

__all__ = [
    "ULPError",
    "ParseError",
    "FormatDetectionError",
    "ConfigurationError",
]


class ULPError(Exception):
    """Base exception for all ULP errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} - {self.details}"
        return self.message


class ParseError(ULPError):
    """Raised when log parsing fails."""

    def __init__(
        self,
        message: str,
        line: str | None = None,
        line_number: int | None = None,
        parser_name: str | None = None,
    ):
        details = {}
        if line is not None:
            details["line"] = line[:100] + "..." if len(line) > 100 else line
        if line_number is not None:
            details["line_number"] = line_number
        if parser_name is not None:
            details["parser"] = parser_name
        super().__init__(message, details)
        self.line = line
        self.line_number = line_number
        self.parser_name = parser_name


class FormatDetectionError(ULPError):
    """Raised when format detection fails."""

    def __init__(
        self,
        message: str,
        file_path: str | None = None,
        candidates: list[tuple[str, float]] | None = None,
    ):
        details = {}
        if file_path is not None:
            details["file_path"] = file_path
        if candidates is not None:
            details["candidates"] = candidates
        super().__init__(message, details)
        self.file_path = file_path
        self.candidates = candidates


class ConfigurationError(ULPError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, config_key: str | None = None):
        details = {}
        if config_key is not None:
            details["config_key"] = config_key
        super().__init__(message, details)
        self.config_key = config_key
