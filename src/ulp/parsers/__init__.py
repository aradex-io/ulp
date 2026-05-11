"""
Parser registry and built-in parsers for ULP.
"""

from typing import Type

from ulp.core.base import BaseParser

__all__ = [
    "ParserRegistry",
    "registry",
    "BaseParser",
]


class ParserRegistry:
    """
    Central registry for all available parsers.

    Manages parser registration and lookup by format name.

    Usage:
        from ulp.parsers import registry

        parser = registry.get_parser("json_structured")
        entries = list(parser.parse_stream(lines))
    """

    def __init__(self):
        """Initialize an empty registry."""
        self._parsers: dict[str, Type[BaseParser]] = {}
        self._format_to_parser: dict[str, str] = {}

    def register(self, parser_class: Type[BaseParser]) -> None:
        """
        Register a parser class.

        Args:
            parser_class: Parser class to register
        """
        # Create instance to get name and formats
        instance = parser_class()
        name = instance.name
        formats = instance.supported_formats

        self._parsers[name] = parser_class

        for fmt in formats:
            self._format_to_parser[fmt] = name

    def get_parser(self, format_name: str) -> BaseParser | None:
        """
        Get a parser instance for the given format.

        Args:
            format_name: Name of the format to parse

        Returns:
            Parser instance or None if not found
        """
        # Check direct format mapping
        parser_name = self._format_to_parser.get(format_name)
        if parser_name and parser_name in self._parsers:
            return self._parsers[parser_name]()

        # Check if format_name is actually a parser name
        if format_name in self._parsers:
            return self._parsers[format_name]()

        return None

    def get_best_parser(self, sample: list[str]) -> tuple[BaseParser | None, float]:
        """
        Find the best parser for the given sample.

        Args:
            sample: List of log lines to analyze

        Returns:
            Tuple of (parser_instance, confidence)
        """
        best_parser: BaseParser | None = None
        best_confidence = 0.0

        for parser_class in self._parsers.values():
            parser = parser_class()
            confidence = parser.can_parse(sample)
            if confidence > best_confidence:
                best_confidence = confidence
                best_parser = parser

        return (best_parser, best_confidence)

    def list_parsers(self) -> list[str]:
        """
        List all registered parser names.

        Returns:
            List of parser names
        """
        return list(self._parsers.keys())

    def list_formats(self) -> list[str]:
        """
        List all supported format names.

        Returns:
            List of format names
        """
        return list(self._format_to_parser.keys())


# Global registry instance
registry = ParserRegistry()


def _register_builtin_parsers() -> None:
    """Register all built-in parsers."""
    # Import here to avoid circular imports
    from ulp.parsers.json_parser import JSONParser
    from ulp.parsers.apache import ApacheCommonParser, ApacheCombinedParser
    from ulp.parsers.nginx import NginxAccessParser, NginxErrorParser
    from ulp.parsers.syslog import SyslogRFC3164Parser, SyslogRFC5424Parser
    from ulp.parsers.python_logging import PythonLoggingParser
    from ulp.parsers.generic import GenericParser
    from ulp.parsers.docker import DockerJSONParser, DockerDaemonParser
    from ulp.parsers.kubernetes import (
        KubernetesContainerParser,
        KubernetesComponentParser,
        KubernetesAuditParser,
        KubernetesEventParser,
    )

    registry.register(JSONParser)
    registry.register(ApacheCommonParser)
    registry.register(ApacheCombinedParser)
    registry.register(NginxAccessParser)
    registry.register(NginxErrorParser)
    registry.register(SyslogRFC3164Parser)
    registry.register(SyslogRFC5424Parser)
    registry.register(PythonLoggingParser)
    registry.register(GenericParser)
    # Docker parsers
    registry.register(DockerJSONParser)
    registry.register(DockerDaemonParser)
    # Kubernetes parsers
    registry.register(KubernetesContainerParser)
    registry.register(KubernetesComponentParser)
    registry.register(KubernetesAuditParser)
    registry.register(KubernetesEventParser)


# Auto-register built-in parsers
_register_builtin_parsers()
