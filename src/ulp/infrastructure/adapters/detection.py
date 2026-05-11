"""
Format detection adapter.

Wraps the existing FormatDetector to implement the FormatDetectorPort.
"""

from ulp.application.ports import FormatDetectorPort
from ulp.detection.detector import FormatDetector

__all__ = ["FormatDetectorAdapter"]


class FormatDetectorAdapter(FormatDetectorPort):
    """
    Adapter that wraps FormatDetector to implement FormatDetectorPort.

    This allows the existing detection logic to be used with the
    application layer use cases.
    """

    def __init__(self, detector: FormatDetector | None = None):
        """
        Initialize the adapter.

        Args:
            detector: Existing FormatDetector instance, or None to create new
        """
        self._detector = detector or FormatDetector()

    def detect(self, sample: list[str]) -> tuple[str, float]:
        """
        Detect log format from sample lines.

        Args:
            sample: Sample of log lines

        Returns:
            Tuple of (format_name, confidence)
        """
        return self._detector.detect(sample)

    def detect_all(self, sample: list[str]) -> list[tuple[str, float]]:
        """
        Get all matching formats ranked by confidence.

        Args:
            sample: Sample of log lines

        Returns:
            List of (format_name, confidence) tuples
        """
        return self._detector.detect_all(sample)
