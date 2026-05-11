"""
Correlate logs use case.

Orchestrates log correlation across multiple sources.
"""

from typing import Iterator
import heapq
from datetime import datetime
from ulp.domain.entities import LogEntry, CorrelationGroup, CorrelationResult
from ulp.domain.services import CorrelationStrategy

__all__ = ["CorrelateLogsUseCase"]


class CorrelateLogsUseCase:
    """
    Use case: Correlate log entries across sources.

    Handles streaming correlation with windowing strategy.
    Can merge multiple sources and apply multiple correlation strategies.

    Example:
        use_case = CorrelateLogsUseCase(
            strategies=[
                RequestIdCorrelation(["request_id", "trace_id"]),
                TimestampWindowCorrelation(window_seconds=1.0),
            ],
            window_size=10000
        )

        sources = [
            parse_file_stream("app.log"),
            parse_file_stream("nginx.log"),
            parse_file_stream("db.log"),
        ]

        result = use_case.execute(sources)
        for group in result.groups:
            print(f"Request {group.correlation_key}: {len(group.entries)} entries")
    """

    def __init__(
        self,
        strategies: list[CorrelationStrategy],
        window_size: int = 10000
    ):
        """
        Initialize the use case.

        Args:
            strategies: List of correlation strategies to apply
            window_size: Maximum entries to buffer (memory management)
        """
        self.strategies = strategies
        self.window_size = window_size

    def execute(
        self,
        sources: list[Iterator[LogEntry]]
    ) -> CorrelationResult:
        """
        Execute correlation across sources.

        Args:
            sources: List of log entry iterators (one per source)

        Returns:
            CorrelationResult with groups and orphan entries
        """
        if not sources:
            return CorrelationResult()

        # Merge sources by timestamp
        merged = self._merge_sources(sources)

        # Collect all entries (for non-streaming strategies)
        # Note: For very large datasets, implement windowed correlation
        all_entries = list(merged)

        # Apply correlation strategies
        all_groups: list[CorrelationGroup] = []
        remaining_entries = all_entries

        for strategy in self.strategies:
            if not remaining_entries:
                break

            groups = list(strategy.correlate(iter(remaining_entries), self.window_size))
            all_groups.extend(groups)

            # Remove correlated entries from remaining
            correlated_ids = {id(e) for g in groups for e in g.entries}
            remaining_entries = [e for e in remaining_entries if id(e) not in correlated_ids]

        return CorrelationResult(
            groups=all_groups,
            orphan_entries=remaining_entries,
        )

    def execute_streaming(
        self,
        sources: list[Iterator[LogEntry]],
        strategy: CorrelationStrategy
    ) -> Iterator[CorrelationGroup]:
        """
        Execute streaming correlation with a single strategy.

        Use this for very large datasets where full buffering isn't possible.

        Args:
            sources: List of log entry iterators
            strategy: Single correlation strategy to apply

        Yields:
            CorrelationGroup objects as they are identified
        """
        if not strategy.supports_streaming():
            raise ValueError(f"Strategy {strategy.name} does not support streaming")

        merged = self._merge_sources(sources)
        yield from strategy.correlate(merged, self.window_size)

    def _merge_sources(
        self,
        sources: list[Iterator[LogEntry]]
    ) -> Iterator[LogEntry]:
        """
        Merge multiple sources, ordered by timestamp.

        Uses a heap to maintain timestamp order across sources.

        Args:
            sources: List of log entry iterators

        Yields:
            LogEntry objects in timestamp order
        """
        # Initialize heap with first entry from each source
        heap: list[tuple[datetime, int, LogEntry, Iterator[LogEntry]]] = []

        for source_id, source in enumerate(sources):
            try:
                entry = next(source)
                # Use current time if no timestamp (preserve order)
                ts = entry.timestamp or datetime.min
                heapq.heappush(heap, (ts, source_id, entry, source))
            except StopIteration:
                pass  # Empty source

        # Emit entries in timestamp order
        while heap:
            ts, source_id, entry, source = heapq.heappop(heap)
            yield entry

            # Get next entry from same source
            try:
                next_entry = next(source)
                next_ts = next_entry.timestamp or datetime.min
                heapq.heappush(heap, (next_ts, source_id, next_entry, source))
            except StopIteration:
                pass  # Source exhausted


class MultiStrategyCorrelation:
    """
    Helper for applying multiple strategies in sequence.

    Strategies are applied in priority order. Earlier strategies
    "claim" entries, removing them from later strategies.
    """

    def __init__(self, strategies: list[CorrelationStrategy]):
        self.strategies = strategies

    def correlate(
        self,
        entries: list[LogEntry]
    ) -> tuple[list[CorrelationGroup], list[LogEntry]]:
        """
        Apply all strategies and return groups + orphans.

        Args:
            entries: Log entries to correlate

        Returns:
            Tuple of (groups, orphan_entries)
        """
        all_groups = []
        remaining = entries

        for strategy in self.strategies:
            if not remaining:
                break

            groups = list(strategy.correlate(iter(remaining)))

            if groups:
                all_groups.extend(groups)

                # Remove correlated entries
                correlated_ids = {id(e) for g in groups for e in g.entries}
                remaining = [e for e in remaining if id(e) not in correlated_ids]

        return all_groups, remaining
