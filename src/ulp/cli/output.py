"""
Output formatters for CLI.
"""

import csv
import json
from io import StringIO

from rich.console import Console
from rich.table import Table

from ulp.core.models import LogEntry, LogLevel
from ulp.core.security import sanitize_csv_cell

__all__ = ["render_entries", "render_table", "render_json", "render_csv", "render_compact"]


# Level color mapping for Rich
LEVEL_STYLES = {
    LogLevel.EMERGENCY: "red bold reverse",
    LogLevel.ALERT: "red bold reverse",
    LogLevel.CRITICAL: "red bold",
    LogLevel.ERROR: "red",
    LogLevel.WARNING: "yellow",
    LogLevel.NOTICE: "blue",
    LogLevel.INFO: "green",
    LogLevel.DEBUG: "dim",
    LogLevel.TRACE: "dim italic",
    LogLevel.UNKNOWN: "white",
}


def render_entries(
    entries: list[LogEntry],
    output_format: str,
    console: Console,
) -> None:
    """
    Render entries in the specified format.

    Args:
        entries: List of LogEntry objects to render
        output_format: One of "table", "json", "csv", "compact"
        console: Rich Console for output
    """
    match output_format:
        case "table":
            render_table(entries, console)
        case "json":
            render_json(entries, console)
        case "csv":
            render_csv(entries)
        case "compact":
            render_compact(entries, console)
        case _:
            render_table(entries, console)


def render_table(entries: list[LogEntry], console: Console) -> None:
    """Render entries as a Rich table."""
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Time", style="dim", width=20)
    table.add_column("Level", width=10)
    table.add_column("Source", width=20)
    table.add_column("Message", overflow="fold")

    for entry in entries:
        # Format timestamp
        time_str = entry.formatted_timestamp("%Y-%m-%d %H:%M:%S")

        # Format level with color
        level_style = LEVEL_STYLES.get(entry.level, "white")
        level_str = f"[{level_style}]{entry.level.name}[/{level_style}]"

        # Format source
        source_parts = []
        if entry.source.service:
            source_parts.append(entry.source.service)
        elif entry.source.file_path:
            source_parts.append(entry.source.file_path.split("/")[-1])
        if entry.source.line_number:
            source_parts.append(f":{entry.source.line_number}")
        source_str = "".join(source_parts) if source_parts else "-"

        # Truncate long messages
        message = entry.message
        if len(message) > 200:
            message = message[:197] + "..."

        table.add_row(time_str, level_str, source_str[:20], message)

    console.print(table)
    console.print(f"\n[dim]Total: {len(entries)} entries[/dim]")


def render_json(entries: list[LogEntry], console: Console) -> None:
    """Render entries as JSON."""
    output = [entry.to_dict() for entry in entries]
    json_str = json.dumps(output, indent=2, default=str)
    console.print(json_str, highlight=False)


def render_csv(entries: list[LogEntry]) -> None:
    """Render entries as CSV to stdout."""
    # Define CSV columns
    fieldnames = [
        "timestamp",
        "level",
        "message",
        "source_file",
        "line_number",
        "service",
        "format",
    ]

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for entry in entries:
        # M4: Sanitize all values to prevent CSV formula injection
        row = {
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
            "level": entry.level.name,
            "message": sanitize_csv_cell(entry.message),
            "source_file": sanitize_csv_cell(entry.source.file_path or ""),
            "line_number": entry.source.line_number or "",
            "service": sanitize_csv_cell(entry.source.service or ""),
            "format": entry.format_detected,
        }
        writer.writerow(row)

    # Print to stdout
    print(output.getvalue(), end="")


def render_compact(entries: list[LogEntry], console: Console) -> None:
    """Render entries in compact single-line format."""
    for entry in entries:
        # Format timestamp
        ts = entry.formatted_timestamp("%H:%M:%S") if entry.timestamp else "--------"

        # Format level with padding
        level = entry.level.name[:5].ljust(5)

        # Get level style
        level_style = LEVEL_STYLES.get(entry.level, "white")

        # Format source
        source = ""
        if entry.source.service:
            source = f"[{entry.source.service}] "

        # Print line
        console.print(
            f"[dim]{ts}[/dim] [{level_style}]{level}[/{level_style}] {source}{entry.message}"
        )
