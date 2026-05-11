"""
Stdin source adapter for ULP.

Provides streaming input from standard input for piped data.
"""

import sys
from typing import Iterator

__all__ = ["StdinStreamSource"]


class StdinStreamSource:
    """
    Streaming source adapter for stdin.

    Reads piped input line-by-line without buffering the entire input.
    Useful for processing output from other commands.

    Example:
        # cat huge.log | ulp parse
        source = StdinStreamSource()
        for line in source.read_lines():
            process(line)
    """

    def __init__(
        self,
        encoding: str = "utf-8",
        errors: str = "replace"
    ):
        """
        Initialize stdin stream source.

        Args:
            encoding: Expected input encoding (default: utf-8)
            errors: How to handle encoding errors (default: replace)
        """
        self.encoding = encoding
        self.errors = errors
        self._line_count = 0
        self._byte_count = 0

    def read_lines(self) -> Iterator[str]:
        """
        Read lines from stdin, yielding one at a time.

        Yields:
            Input lines (without trailing newline)
        """
        # Use binary mode for consistent handling across platforms
        for line in sys.stdin:
            self._line_count += 1
            self._byte_count += len(line.encode(self.encoding, errors="replace"))
            yield line.rstrip("\n\r")

    def metadata(self) -> dict[str, str]:
        """
        Get source metadata.

        Note: Size is not known until reading completes.
        """
        return {
            "source_type": "stdin",
            "path": "<stdin>",
            "name": "stdin",
            "lines_read": str(self._line_count),
            "bytes_read": str(self._byte_count),
        }


class BufferedStdinSource:
    """
    Buffered stdin source with peek capability.

    Buffers initial lines for format detection while still
    providing streaming access to all data.

    Example:
        source = BufferedStdinSource(peek_lines=50)
        sample = source.peek()  # Get first 50 lines for detection
        for line in source.read_lines():  # Includes peeked lines
            process(line)
    """

    def __init__(
        self,
        peek_lines: int = 50,
        encoding: str = "utf-8",
        errors: str = "replace"
    ):
        """
        Initialize buffered stdin source.

        Args:
            peek_lines: Number of lines to buffer for peeking
            encoding: Expected input encoding
            errors: How to handle encoding errors
        """
        self.peek_lines = peek_lines
        self.encoding = encoding
        self.errors = errors
        self._buffer: list[str] = []
        self._peeked = False
        self._exhausted = False
        self._line_count = 0

    def peek(self) -> list[str]:
        """
        Peek at the first N lines without consuming them.

        Can only be called once, before read_lines().

        Returns:
            List of first peek_lines lines
        """
        if self._peeked:
            return self._buffer

        self._peeked = True
        count = 0

        for line in sys.stdin:
            stripped = line.rstrip("\n\r")
            self._buffer.append(stripped)
            count += 1
            if count >= self.peek_lines:
                break
        else:
            # stdin exhausted during peek
            self._exhausted = True

        return self._buffer

    def read_lines(self) -> Iterator[str]:
        """
        Read all lines, including any peeked lines.

        Yields:
            Input lines (without trailing newline)
        """
        # First yield buffered lines
        for line in self._buffer:
            self._line_count += 1
            yield line

        # Then continue with remaining stdin (if not exhausted)
        if not self._exhausted:
            for line in sys.stdin:
                self._line_count += 1
                yield line.rstrip("\n\r")

    def metadata(self) -> dict[str, str]:
        """Get source metadata."""
        return {
            "source_type": "stdin_buffered",
            "path": "<stdin>",
            "name": "stdin",
            "peek_lines": str(self.peek_lines),
            "lines_read": str(self._line_count),
        }
