"""
File source adapters for ULP.

Provides memory-efficient streaming for files of any size.
"""

from pathlib import Path
from typing import Callable, Iterator

from ulp.core.security import (
    MAX_LINE_LENGTH,
    validate_line_length,
    check_symlink,
)

__all__ = ["FileStreamSource", "LargeFileStreamSource"]


class FileStreamSource:
    """
    Memory-efficient file streaming adapter.

    Reads files line-by-line without loading the entire file into memory.
    Suitable for files up to a few GB.

    Example:
        source = FileStreamSource("/var/log/app.log")
        for line in source.read_lines():
            print(line)
    """

    def __init__(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        errors: str = "replace",
        warn_symlinks: bool = True,
    ):
        """
        Initialize file stream source.

        Args:
            path: Path to log file
            encoding: File encoding (default: utf-8)
            errors: How to handle encoding errors (default: replace)
            warn_symlinks: Emit warning when following symlinks (default: True)
        """
        self.path = Path(path)
        self.encoding = encoding
        self.errors = errors

        if not self.path.exists():
            raise FileNotFoundError(f"File not found: {self.path}")

        # M6: Check for symlinks and warn
        is_symlink, resolved = check_symlink(self.path, warn=warn_symlinks)
        if is_symlink:
            self.path = resolved

    def read_lines(self) -> Iterator[str]:
        """
        Read lines from file, yielding one at a time.

        Yields:
            Log lines (without trailing newline)

        Raises:
            LineTooLongError: If a line exceeds MAX_LINE_LENGTH
        """
        with open(
            self.path,
            "r",
            encoding=self.encoding,
            errors=self.errors
        ) as f:
            for line in f:
                stripped = line.rstrip("\n\r")
                # H1: Validate line length
                validate_line_length(stripped)
                yield stripped

    def metadata(self) -> dict[str, str]:
        """Get source metadata."""
        stat = self.path.stat()
        return {
            "source_type": "file",
            "path": str(self.path.absolute()),
            "name": self.path.name,
            "size_bytes": str(stat.st_size),
            "size_mb": f"{stat.st_size / (1024 * 1024):.2f}",
        }


class LargeFileStreamSource:
    """
    Memory-mapped file streaming for very large files (1-10GB+).

    Uses mmap for files over the threshold, providing efficient
    random access without loading the entire file into memory.

    Example:
        source = LargeFileStreamSource("/var/log/huge.log")
        for line in source.read_lines():
            process(line)
    """

    # 100MB threshold for switching to mmap
    MMAP_THRESHOLD = 100 * 1024 * 1024

    def __init__(
        self,
        path: str | Path,
        encoding: str = "utf-8",
        errors: str = "replace",
        chunk_size: int = 8192,
        warn_symlinks: bool = True,
    ):
        """
        Initialize large file stream source.

        Args:
            path: Path to log file
            encoding: File encoding (default: utf-8)
            errors: How to handle encoding errors (default: replace)
            chunk_size: Read chunk size for mmap mode
            warn_symlinks: Emit warning when following symlinks (default: True)
        """
        self.path = Path(path)
        self.encoding = encoding
        self.errors = errors
        self.chunk_size = chunk_size

        if not self.path.exists():
            raise FileNotFoundError(f"File not found: {self.path}")

        # M6: Check for symlinks and warn
        is_symlink, resolved = check_symlink(self.path, warn=warn_symlinks)
        if is_symlink:
            self.path = resolved

        self._file_size = self.path.stat().st_size
        self._use_mmap = self._file_size > self.MMAP_THRESHOLD

    def read_lines(self) -> Iterator[str]:
        """
        Read lines from file using the most efficient method.

        For files > 100MB, uses memory mapping.
        For smaller files, uses regular file iteration.

        Yields:
            Log lines (without trailing newline)
        """
        if self._use_mmap:
            yield from self._read_lines_mmap()
        else:
            yield from self._read_lines_regular()

    def _read_lines_regular(self) -> Iterator[str]:
        """Read using standard file iteration."""
        with open(
            self.path,
            "r",
            encoding=self.encoding,
            errors=self.errors
        ) as f:
            for line in f:
                stripped = line.rstrip("\n\r")
                # H1: Validate line length
                validate_line_length(stripped)
                yield stripped

    def _read_lines_mmap(self) -> Iterator[str]:
        """Read using memory mapping for large files."""
        import mmap

        with open(self.path, "rb") as f:
            # Create memory map
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                buffer = bytearray()
                position = 0

                while position < len(mm):
                    # Read in chunks
                    chunk_end = min(position + self.chunk_size, len(mm))
                    chunk = mm[position:chunk_end]

                    # Process bytes
                    for byte in chunk:
                        if byte == ord("\n"):
                            # Found line end
                            try:
                                line = buffer.decode(self.encoding, errors=self.errors)
                                stripped = line.rstrip("\r")
                                # H1: Validate line length
                                validate_line_length(stripped)
                                yield stripped
                            except UnicodeDecodeError:
                                # Skip malformed lines
                                pass
                            buffer = bytearray()
                        else:
                            buffer.append(byte)

                    position = chunk_end

                # Yield final line if no trailing newline
                if buffer:
                    try:
                        line = buffer.decode(self.encoding, errors=self.errors)
                        stripped = line.rstrip("\r")
                        # H1: Validate line length
                        validate_line_length(stripped)
                        yield stripped
                    except UnicodeDecodeError:
                        pass

    def metadata(self) -> dict[str, str]:
        """Get source metadata."""
        return {
            "source_type": "large_file" if self._use_mmap else "file",
            "path": str(self.path.absolute()),
            "name": self.path.name,
            "size_bytes": str(self._file_size),
            "size_mb": f"{self._file_size / (1024 * 1024):.2f}",
            "size_gb": f"{self._file_size / (1024 * 1024 * 1024):.2f}",
            "using_mmap": str(self._use_mmap),
        }


class ChunkedFileStreamSource:
    """
    Chunked file streaming with progress tracking.

    Provides callbacks for monitoring progress when processing large files.

    Example:
        def on_progress(bytes_read, total_bytes, lines_read):
            pct = bytes_read / total_bytes * 100
            print(f"Progress: {pct:.1f}% ({lines_read} lines)")

        source = ChunkedFileStreamSource("/var/log/huge.log", on_progress)
        for line in source.read_lines():
            process(line)
    """

    def __init__(
        self,
        path: str | Path,
        progress_callback: Callable | None = None,
        encoding: str = "utf-8",
        errors: str = "replace",
        callback_interval: int = 10000,
        warn_symlinks: bool = True,
    ):
        """
        Initialize chunked file stream source.

        Args:
            path: Path to log file
            progress_callback: Callback(bytes_read, total_bytes, lines_read)
            encoding: File encoding
            errors: How to handle encoding errors
            callback_interval: Call progress callback every N lines
            warn_symlinks: Emit warning when following symlinks (default: True)
        """
        self.path = Path(path)
        self.progress_callback = progress_callback
        self.encoding = encoding
        self.errors = errors
        self.callback_interval = callback_interval

        if not self.path.exists():
            raise FileNotFoundError(f"File not found: {self.path}")

        # M6: Check for symlinks and warn
        is_symlink, resolved = check_symlink(self.path, warn=warn_symlinks)
        if is_symlink:
            self.path = resolved

        self._file_size = self.path.stat().st_size

    def read_lines(self) -> Iterator[str]:
        """Read lines with progress tracking."""
        bytes_read = 0
        lines_read = 0

        with open(
            self.path,
            "r",
            encoding=self.encoding,
            errors=self.errors
        ) as f:
            for line in f:
                bytes_read += len(line.encode(self.encoding, errors="replace"))
                lines_read += 1

                stripped = line.rstrip("\n\r")
                # H1: Validate line length
                validate_line_length(stripped)
                yield stripped

                # Report progress
                if (
                    self.progress_callback and
                    lines_read % self.callback_interval == 0
                ):
                    self.progress_callback(
                        bytes_read,
                        self._file_size,
                        lines_read
                    )

        # Final progress callback
        if self.progress_callback:
            self.progress_callback(bytes_read, self._file_size, lines_read)

    def metadata(self) -> dict[str, str]:
        """Get source metadata."""
        return {
            "source_type": "chunked_file",
            "path": str(self.path.absolute()),
            "name": self.path.name,
            "size_bytes": str(self._file_size),
            "size_mb": f"{self._file_size / (1024 * 1024):.2f}",
        }
