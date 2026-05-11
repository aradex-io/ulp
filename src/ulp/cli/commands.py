"""
CLI commands using the application layer use cases.

This module provides the CLI command implementations that wire up
the infrastructure adapters to the application use cases.
"""

import sys
from pathlib import Path
from typing import Iterator

from rich.console import Console

from ulp.core.models import LogEntry, LogLevel
from ulp.core.security import validate_regex_pattern, SecurityValidationError
from ulp.application.parse_logs import ParseLogsUseCase
from ulp.application.correlate_logs import CorrelateLogsUseCase
from ulp.infrastructure import (
    FileStreamSource,
    LargeFileStreamSource,
    BufferedStdinSource,
    FormatDetectorAdapter,
    ParserRegistryAdapter,
    NormalizationPipeline,
    TimestampNormalizer,
    LevelNormalizer,
    RequestIdCorrelation,
    TimestampWindowCorrelation,
    SessionCorrelation,
)
from ulp.cli.output import render_entries

__all__ = ["parse_command", "correlate_command", "stream_command"]


def create_source(file_path: str | None, use_mmap: bool = True):
    """
    Create appropriate source adapter for the input.

    Args:
        file_path: Path to file, or None for stdin
        use_mmap: Use memory-mapped I/O for large files

    Returns:
        Source adapter instance
    """
    if file_path is None or file_path == "-":
        return BufferedStdinSource(peek_lines=50)

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Use LargeFileStreamSource for files > 100MB
    if use_mmap and path.stat().st_size > 100 * 1024 * 1024:
        return LargeFileStreamSource(path)

    return FileStreamSource(path)


def parse_command(
    files: tuple[str, ...],
    log_format: str | None,
    output_format: str,
    level: str | None,
    limit: int | None,
    grep: str | None,
    normalize: bool,
    quiet: bool,
    console: Console,
    error_console: Console,
) -> int:
    """
    Execute the parse command using application layer.

    Returns:
        Exit code (0 = success, 1 = error)
    """
    # Create adapters
    detector = FormatDetectorAdapter()
    registry = ParserRegistryAdapter()

    # Create normalizer if requested
    normalizer = None
    if normalize:
        normalizer = NormalizationPipeline([
            TimestampNormalizer(target_tz="UTC"),
            LevelNormalizer(),
        ])

    all_entries: list[LogEntry] = []

    # Handle stdin
    if not files:
        if sys.stdin.isatty():
            error_console.print("[red]Error:[/red] No files specified")
            return 1

        source = BufferedStdinSource(peek_lines=50)
        use_case = ParseLogsUseCase(
            source=source,
            parser_registry=registry,
            format_detector=detector,
            normalizer=normalizer,
        )

        try:
            for entry in use_case.execute(format_hint=log_format):
                all_entries.append(entry)
        except ValueError as e:
            error_console.print(f"[red]Error:[/red] {e}")
            return 1
    else:
        # Process each file
        for file_path in files:
            try:
                source = create_source(file_path)

                # Show detection info
                if not log_format and not quiet:
                    sample = source.peek() if hasattr(source, 'peek') else []
                    if sample:
                        detected, confidence = detector.detect(sample)
                        console.print(
                            f"[dim]{Path(file_path).name}:[/dim] "
                            f"Detected [cyan]{detected}[/cyan] "
                            f"(confidence: {confidence:.0%})"
                        )

                use_case = ParseLogsUseCase(
                    source=source,
                    parser_registry=registry,
                    format_detector=detector,
                    normalizer=normalizer,
                )

                for entry in use_case.execute(format_hint=log_format):
                    all_entries.append(entry)

            except FileNotFoundError as e:
                error_console.print(f"[red]Error:[/red] {e}")
                continue
            except ValueError as e:
                error_console.print(f"[red]Parse error in {file_path}:[/red] {e}")
                continue

    # Apply filters
    if level:
        min_level = LogLevel.from_string(level)
        all_entries = [e for e in all_entries if e.level >= min_level]

    if grep:
        # M2: Validate regex pattern for security (length, syntax, ReDoS)
        try:
            pattern = validate_regex_pattern(grep)
            all_entries = [e for e in all_entries if pattern.search(e.message)]
        except SecurityValidationError as e:
            error_console.print(f"[red]Regex validation failed:[/red] {e.message}")
            return 1

    if limit:
        all_entries = all_entries[:limit]

    # Render output
    if all_entries:
        render_entries(all_entries, output_format, console)
    elif not quiet:
        console.print("[yellow]No matching log entries found.[/yellow]")

    return 0


def correlate_command(
    files: tuple[str, ...],
    log_format: str | None,
    strategy: str,
    window: float,
    output_format: str,
    quiet: bool,
    console: Console,
    error_console: Console,
) -> int:
    """
    Execute the correlate command.

    Correlates log entries across multiple files using the specified strategy.

    Returns:
        Exit code
    """
    if len(files) < 2:
        error_console.print(
            "[red]Error:[/red] Correlation requires at least 2 files"
        )
        return 1

    # Create adapters
    detector = FormatDetectorAdapter()
    registry = ParserRegistryAdapter()

    # Create correlation strategies
    strategies = []
    if strategy == "request_id" or strategy == "all":
        strategies.append(RequestIdCorrelation())
    if strategy == "timestamp" or strategy == "all":
        strategies.append(TimestampWindowCorrelation(window_seconds=window))
    if strategy == "session" or strategy == "all":
        strategies.append(SessionCorrelation())

    if not strategies:
        error_console.print(f"[red]Unknown strategy:[/red] {strategy}")
        return 1

    # Create entry iterators for each file
    entry_iterators: list[Iterator[LogEntry]] = []

    for file_path in files:
        try:
            source = create_source(file_path)
            use_case = ParseLogsUseCase(
                source=source,
                parser_registry=registry,
                format_detector=detector,
            )
            entry_iterators.append(use_case.execute(format_hint=log_format))

            if not quiet:
                console.print(f"[dim]Added source:[/dim] {file_path}")

        except (FileNotFoundError, ValueError) as e:
            error_console.print(f"[red]Error with {file_path}:[/red] {e}")
            continue

    if len(entry_iterators) < 2:
        error_console.print(
            "[red]Error:[/red] Need at least 2 valid sources for correlation"
        )
        return 1

    # Execute correlation
    correlate_use_case = CorrelateLogsUseCase(
        strategies=strategies,
        window_size=10000,
    )

    result = correlate_use_case.execute(entry_iterators)

    # Display results
    if not quiet:
        console.print("\n[bold]Correlation Results[/bold]")
        console.print(f"  Groups found: [cyan]{len(result.groups)}[/cyan]")
        console.print(f"  Orphan entries: [yellow]{len(result.orphan_entries)}[/yellow]")

    if output_format == "json":
        import json
        output = {
            "groups": [
                {
                    "id": str(g.id),
                    "correlation_key": g.correlation_key,
                    "correlation_type": g.correlation_type,
                    "entry_count": len(g.entries),
                    "sources": list(g.sources),
                    "time_range": [
                        g.time_range[0].isoformat() if g.time_range else None,
                        g.time_range[1].isoformat() if g.time_range else None,
                    ],
                }
                for g in result.groups
            ],
            "orphan_count": len(result.orphan_entries),
        }
        console.print(json.dumps(output, indent=2))
    else:
        # Table format
        from rich.table import Table
        table = Table(title="Correlation Groups")
        table.add_column("Key", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Entries", justify="right")
        table.add_column("Sources")
        table.add_column("Time Range")

        for group in result.groups[:50]:  # Limit display
            time_range = ""
            if group.time_range:
                start = group.time_range[0].strftime("%H:%M:%S")
                end = group.time_range[1].strftime("%H:%M:%S")
                time_range = f"{start} - {end}"

            table.add_row(
                group.correlation_key[:30],
                group.correlation_type,
                str(len(group.entries)),
                ", ".join(s.split("/")[-1] for s in list(group.sources)[:3]),
                time_range,
            )

        console.print(table)

    return 0


def stream_command(
    file_path: str,
    log_format: str,
    output_format: str,
    progress: bool,
    console: Console,
    error_console: Console,
) -> int:
    """
    Execute streaming parse for very large files.

    This command is optimized for files > 1GB where buffering
    isn't feasible.

    Returns:
        Exit code
    """
    from ulp.application.parse_logs import ParseLogsStreamingUseCase
    from ulp.infrastructure import ChunkedFileStreamSource

    try:
        # Use chunked source with progress tracking
        def on_progress(bytes_read: int, total_bytes: int, lines: int) -> None:
            if progress:
                pct = bytes_read / total_bytes * 100
                console.print(
                    f"\r[dim]Progress: {pct:.1f}% ({lines:,} lines)[/dim]",
                    end=""
                )

        source = ChunkedFileStreamSource(
            file_path,
            progress_callback=on_progress if progress else None,
        )

        registry = ParserRegistryAdapter()
        use_case = ParseLogsStreamingUseCase(
            source=source,
            parser_registry=registry,
        )

        # Stream output
        count = 0
        for entry in use_case.execute(format_name=log_format):
            if output_format == "json":
                import json
                print(json.dumps(entry.to_dict(), default=str))
            else:
                # Compact single-line output for streaming
                ts = entry.formatted_timestamp("%H:%M:%S") if entry.timestamp else "--------"
                level = entry.level.name[:5].ljust(5)
                print(f"{ts} {level} {entry.message}")

            count += 1

        if progress:
            console.print()  # Newline after progress
            console.print(f"[green]Processed {count:,} entries[/green]")

        return 0

    except FileNotFoundError as e:
        error_console.print(f"[red]Error:[/red] {e}")
        return 1
    except ValueError as e:
        error_console.print(f"[red]Parse error:[/red] {e}")
        return 1
