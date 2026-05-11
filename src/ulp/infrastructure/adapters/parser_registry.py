"""
Parser registry adapter.

Wraps the existing ParserRegistry to implement the ParserRegistry port.
"""

from ulp.application.ports import ParserRegistry as ParserRegistryPort
from ulp.domain.services import LogParser
from ulp.parsers import registry as global_registry

__all__ = ["ParserRegistryAdapter"]


class ParserRegistryAdapter(ParserRegistryPort):
    """
    Adapter that wraps the global parser registry.

    Implements the ParserRegistry port for use with application layer.
    """

    def __init__(self):
        """Initialize the adapter with the global registry."""
        self._registry = global_registry

    def get_parser(self, format_name: str) -> LogParser | None:
        """
        Get a parser for the given format.

        Args:
            format_name: Name of the log format

        Returns:
            Parser instance or None if not found
        """
        parser = self._registry.get_parser(format_name)
        if parser is None:
            return None
        # BaseParser from ulp.core.base implements the same interface
        # as LogParser protocol, so we can return it directly
        return parser  # type: ignore

    def list_parsers(self) -> list[str]:
        """List all registered parser names."""
        return self._registry.list_parsers()

    def list_formats(self) -> list[str]:
        """List all supported format names."""
        return self._registry.list_formats()
