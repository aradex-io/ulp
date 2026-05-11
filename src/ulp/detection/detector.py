"""
Format detection engine for automatically identifying log formats.
"""

import itertools
import json
import re
from typing import Iterator

from ulp.core.models import FormatSignature
from ulp.detection.signatures import BUILTIN_SIGNATURES

__all__ = ["FormatDetector"]


class FormatDetector:
    """
    Automatically detect log format from content samples.

    Uses signature matching with confidence scoring to identify
    the most likely log format.

    Usage:
        detector = FormatDetector()
        format_name, confidence = detector.detect_file("access.log")
    """

    def __init__(self, signatures: list[FormatSignature] | None = None):
        """
        Initialize the detector.

        Args:
            signatures: List of format signatures to use.
                       Defaults to BUILTIN_SIGNATURES.
        """
        self.signatures = signatures or BUILTIN_SIGNATURES
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        self._compile_all_patterns()
        self._sample_size = 50

    def _compile_all_patterns(self) -> None:
        """Pre-compile all regex patterns for performance."""
        for sig in self.signatures:
            magic_compiled = []
            for pattern in sig.magic_patterns:
                try:
                    magic_compiled.append(re.compile(pattern))
                except re.error:
                    pass  # Skip invalid patterns

            line_compiled = []
            for pattern in sig.line_patterns:
                try:
                    line_compiled.append(re.compile(pattern))
                except re.error:
                    pass

            self._compiled_patterns[sig.name] = {
                "magic": magic_compiled,
                "line": line_compiled,
            }

    def detect(
        self,
        lines: Iterator[str] | list[str],
        sample_size: int | None = None
    ) -> tuple[str, float]:
        """
        Detect format from lines.

        Args:
            lines: Iterator or list of log lines
            sample_size: Number of lines to analyze (default 50)

        Returns:
            Tuple of (format_name, confidence) where confidence is 0.0-1.0
        """
        sample_size = sample_size or self._sample_size

        # Collect sample
        if isinstance(lines, list):
            sample = lines[:sample_size]
        else:
            sample = list(itertools.islice(lines, sample_size))

        # Filter empty lines
        sample = [line.strip() for line in sample if line.strip()]

        if not sample:
            return ("unknown", 0.0)

        # Score each signature
        scores: dict[str, float] = {}

        for sig in self.signatures:
            score = self._score_signature(sig, sample)
            if score > 0:
                scores[sig.name] = score

        if not scores:
            return ("generic", 0.3)

        # Normalize scores to confidence values
        max_score = max(scores.values())
        best_format = max(scores.items(), key=lambda x: x[1])

        # Calculate confidence (0.0 to 1.0)
        # Higher score relative to max = higher confidence
        confidence = min(1.0, best_format[1] / max(max_score, 1.0))

        return (best_format[0], confidence)

    def detect_file(self, file_path: str) -> tuple[str, float]:
        """
        Detect format from a file.

        Args:
            file_path: Path to the log file

        Returns:
            Tuple of (format_name, confidence)
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= self._sample_size:
                        break
                    lines.append(line)
                return self.detect(lines)
        except (IOError, OSError):
            return ("unknown", 0.0)

    def detect_all(
        self,
        lines: Iterator[str] | list[str],
        sample_size: int | None = None
    ) -> list[tuple[str, float]]:
        """
        Get all matching formats ranked by confidence.

        Args:
            lines: Iterator or list of log lines
            sample_size: Number of lines to analyze

        Returns:
            List of (format_name, confidence) tuples, sorted by confidence desc
        """
        sample_size = sample_size or self._sample_size

        if isinstance(lines, list):
            sample = lines[:sample_size]
        else:
            sample = list(itertools.islice(lines, sample_size))

        sample = [line.strip() for line in sample if line.strip()]

        if not sample:
            return [("unknown", 0.0)]

        scores: dict[str, float] = {}

        for sig in self.signatures:
            score = self._score_signature(sig, sample)
            if score > 0:
                scores[sig.name] = score

        if not scores:
            return [("generic", 0.3)]

        max_score = max(scores.values())

        results = [
            (name, min(1.0, score / max(max_score, 1.0)))
            for name, score in scores.items()
        ]

        return sorted(results, key=lambda x: x[1], reverse=True)

    def _score_signature(self, sig: FormatSignature, sample: list[str]) -> float:
        """
        Calculate a score for how well a signature matches the sample.

        Args:
            sig: Format signature to test
            sample: Sample log lines

        Returns:
            Score value (higher = better match)
        """
        score = 0.0
        patterns = self._compiled_patterns.get(sig.name, {"magic": [], "line": []})

        # Check for JSON structure if signature expects it
        if sig.is_json:
            json_score = self._check_json_structure(sample)
            if json_score > 0.5:
                score += json_score * sig.weight * 2.0
            else:
                # If it's supposed to be JSON but isn't, no match
                return 0.0

        # Magic patterns (high weight - unique identifiers)
        magic_matches = 0
        for line in sample:
            for pattern in patterns["magic"]:
                if pattern.match(line):
                    magic_matches += 1
                    break  # Count each line once

        if magic_matches > 0:
            magic_ratio = magic_matches / len(sample)
            score += magic_ratio * sig.weight * 3.0

        # Line patterns (lower weight - common characteristics)
        line_matches = 0
        for line in sample:
            for pattern in patterns["line"]:
                if pattern.search(line):
                    line_matches += 1
                    break

        if line_matches > 0:
            line_ratio = line_matches / len(sample)
            score += line_ratio * sig.weight * 1.0

        return score

    def _check_json_structure(self, sample: list[str]) -> float:
        """
        Check what proportion of lines are valid JSON objects.

        Args:
            sample: Sample log lines

        Returns:
            Ratio of valid JSON lines (0.0 to 1.0)
        """
        if not sample:
            return 0.0

        json_count = 0
        for line in sample:
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    json.loads(line)
                    json_count += 1
                except json.JSONDecodeError:
                    pass

        return json_count / len(sample)
