"""
Source adapters for ULP.

These implement the LogSourcePort interface for various input sources.
"""

from ulp.infrastructure.sources.file_source import (
    FileStreamSource,
    LargeFileStreamSource,
    ChunkedFileStreamSource,
)
from ulp.infrastructure.sources.stdin_source import (
    StdinStreamSource,
    BufferedStdinSource,
)

__all__ = [
    "FileStreamSource",
    "LargeFileStreamSource",
    "ChunkedFileStreamSource",
    "StdinStreamSource",
    "BufferedStdinSource",
]
