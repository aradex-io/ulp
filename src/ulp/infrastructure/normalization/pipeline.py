"""
Normalization pipeline implementation.

Orchestrates multiple normalization steps in sequence.
"""

from typing import Iterator
from ulp.domain.entities import LogEntry
from ulp.domain.services import NormalizationStep
from ulp.application.ports import NormalizerPort

__all__ = ["NormalizationPipeline"]


class NormalizationPipeline(NormalizerPort):
    """
    Chain-of-responsibility pipeline for log normalization.

    Applies multiple normalization steps in sequence, allowing each
    step to transform or enrich log entries.

    Example:
        pipeline = NormalizationPipeline([
            TimestampNormalizer(target_tz="UTC"),
            LevelNormalizer(),
            FieldNormalizer(field_mappings),
        ])

        for entry in pipeline.process(raw_entries):
            # Entry is now normalized
            print(entry.timestamp)  # Always UTC
    """

    def __init__(
        self,
        steps: list[NormalizationStep] | None = None,
        stop_on_error: bool = False
    ):
        """
        Initialize the normalization pipeline.

        Args:
            steps: List of normalization steps to apply
            stop_on_error: If True, stop pipeline on first error
        """
        self.steps = steps or []
        self.stop_on_error = stop_on_error
        self._error_count = 0
        self._processed_count = 0

    def add_step(self, step: NormalizationStep) -> "NormalizationPipeline":
        """
        Add a step to the pipeline.

        Returns self for chaining.
        """
        self.steps.append(step)
        return self

    def process(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        """
        Process entries through the normalization pipeline.

        Args:
            entries: Raw log entries

        Yields:
            Normalized log entries
        """
        for entry in entries:
            try:
                normalized = self._apply_steps(entry)
                self._processed_count += 1
                yield normalized
            except Exception as e:
                self._error_count += 1
                if self.stop_on_error:
                    raise
                # On error, yield original entry with error marker
                entry.metadata["normalization_error"] = str(e)
                yield entry

    def process_one(self, entry: LogEntry) -> LogEntry:
        """
        Process a single entry through the pipeline.

        Args:
            entry: Single log entry

        Returns:
            Normalized entry
        """
        return self._apply_steps(entry)

    def _apply_steps(self, entry: LogEntry) -> LogEntry:
        """Apply all steps to an entry."""
        result = entry
        for step in self.steps:
            result = step.normalize(result)
        return result

    @property
    def stats(self) -> dict[str, int]:
        """Get processing statistics."""
        return {
            "processed": self._processed_count,
            "errors": self._error_count,
            "steps": len(self.steps),
        }

    def reset_stats(self) -> None:
        """Reset processing statistics."""
        self._processed_count = 0
        self._error_count = 0


class ConditionalPipeline(NormalizerPort):
    """
    Pipeline that applies steps conditionally based on entry attributes.

    Example:
        pipeline = ConditionalPipeline()
        pipeline.when(
            lambda e: e.source.file_path and "nginx" in e.source.file_path,
            NginxFieldNormalizer()
        )
        pipeline.when(
            lambda e: e.level == LogLevel.ERROR,
            ErrorEnricher()
        )
    """

    def __init__(self):
        self._rules: list[tuple[callable, NormalizationStep]] = []
        self._default_steps: list[NormalizationStep] = []

    def when(
        self,
        condition: callable,
        step: NormalizationStep
    ) -> "ConditionalPipeline":
        """
        Add a conditional step.

        Args:
            condition: Function(LogEntry) -> bool
            step: Step to apply when condition is true

        Returns:
            Self for chaining
        """
        self._rules.append((condition, step))
        return self

    def always(self, step: NormalizationStep) -> "ConditionalPipeline":
        """Add a step that always applies."""
        self._default_steps.append(step)
        return self

    def process(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        """Process entries with conditional normalization."""
        for entry in entries:
            yield self.process_one(entry)

    def process_one(self, entry: LogEntry) -> LogEntry:
        """Process single entry."""
        result = entry

        # Apply default steps first
        for step in self._default_steps:
            result = step.normalize(result)

        # Apply conditional steps
        for condition, step in self._rules:
            try:
                if condition(result):
                    result = step.normalize(result)
            except Exception:
                # Condition evaluation failed, skip step
                pass

        return result
