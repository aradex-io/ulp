"""
Format detection engine for ULP.
"""

from ulp.detection.detector import FormatDetector
from ulp.detection.signatures import BUILTIN_SIGNATURES

__all__ = [
    "FormatDetector",
    "BUILTIN_SIGNATURES",
    "detect_format",
]


def detect_format(file_path: str) -> tuple[str, float]:
    """
    Detect the log format of a file.

    Args:
        file_path: Path to the log file

    Returns:
        Tuple of (format_name, confidence)
    """
    detector = FormatDetector()
    return detector.detect_file(file_path)
