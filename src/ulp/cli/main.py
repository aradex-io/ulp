"""
Main CLI entry point for ULP.

Uses the clean architecture with application layer use cases
and infrastructure adapters.
"""

from pathlib import Path

import click
from rich.console import Console

from ulp import __version__

console = Console()
error_console = Console(stderr=True)


@click.group()
@click.version_option(version=__version__, prog_name="ulp")
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def cli(ctx: click.Context, quiet: bool) -> None:
    """
    ULP - Universal Log Parser

    Automatically detect, parse, and analyze logs from any format.
    Now with streaming support for large files (1-10GB+) and
    cross-source log correlation.

    Examples:

    \b
        ulp parse access.log
        ulp parse --format json_structured app.log
        ulp detect /var/log/syslog
        ulp parse --level error --output json *.log
        ulp correlate --strategy request_id app.log nginx.log
        ulp stream --format docker_json huge-container.log
    """
    ctx.ensure_object(dict)
    ctx.obj["quiet"] = quiet
    ctx.obj["console"] = console
    ctx.obj["error_console"] = error_console


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option(
    "--format", "-f", "log_format",
    help="Force a specific log format (skip auto-detection)"
)
@click.option(
    "--output", "-o", "output_format",
    type=click.Choice(["table", "json", "csv", "compact"]),
    default="table",
    help="Output format (default: table)"
)
@click.option(
    "--level", "-l",
    type=click.Choice(["debug", "info", "warning", "error", "critical"], case_sensitive=False),
    help="Filter by minimum log level"
)
@click.option(
    "--limit", "-n", type=int,
    help="Limit number of entries to display"
)
@click.option(
    "--grep", "-g",
    help="Filter entries by message content (regex)"
)
@click.option(
    "--normalize/--no-normalize", default=False,
    help="Apply normalization pipeline (timestamps to UTC, level normalization)"
)
@click.pass_context
def parse(
    ctx: click.Context,
    files: tuple[str, ...],
    log_format: str | None,
    output_format: str,
    level: str | None,
    limit: int | None,
    grep: str | None,
    normalize: bool,
) -> None:
    """
    Parse log files and display normalized output.

    Pass one or more log files to parse. If no format is specified,
    ULP will auto-detect the format.

    Examples:

    \b
        ulp parse access.log
        ulp parse --format apache_combined *.log
        ulp parse --level error --output json app.log
        ulp parse --grep "ERROR|WARN" app.log
        ulp parse --normalize app.log  # Normalize timestamps to UTC
    """
    from ulp.cli.commands import parse_command

    quiet = ctx.obj.get("quiet", False)
    exit_code = parse_command(
        files=files,
        log_format=log_format,
        output_format=output_format,
        level=level,
        limit=limit,
        grep=grep,
        normalize=normalize,
        quiet=quiet,
        console=ctx.obj["console"],
        error_console=ctx.obj["error_console"],
    )
    ctx.exit(exit_code)


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True), required=True)
@click.option(
    "--format", "-f", "log_format",
    help="Force a specific log format for all files"
)
@click.option(
    "--strategy", "-s",
    type=click.Choice(["request_id", "timestamp", "session", "all"]),
    default="all",
    help="Correlation strategy (default: all)"
)
@click.option(
    "--window", "-w", type=float, default=1.0,
    help="Time window in seconds for timestamp correlation (default: 1.0)"
)
@click.option(
    "--output", "-o", "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format (default: table)"
)
@click.pass_context
def correlate(
    ctx: click.Context,
    files: tuple[str, ...],
    log_format: str | None,
    strategy: str,
    window: float,
    output_format: str,
) -> None:
    """
    Correlate logs across multiple files.

    Groups related log entries by request ID, timestamp proximity,
    or session identifier.

    Examples:

    \b
        ulp correlate app.log nginx.log db.log
        ulp correlate --strategy request_id *.log
        ulp correlate --strategy timestamp --window 0.5 app.log web.log
        ulp correlate --output json app.log nginx.log
    """
    from ulp.cli.commands import correlate_command

    quiet = ctx.obj.get("quiet", False)
    exit_code = correlate_command(
        files=files,
        log_format=log_format,
        strategy=strategy,
        window=window,
        output_format=output_format,
        quiet=quiet,
        console=ctx.obj["console"],
        error_console=ctx.obj["error_console"],
    )
    ctx.exit(exit_code)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "log_format", required=True,
    help="Log format (required - no auto-detection in stream mode)"
)
@click.option(
    "--output", "-o", "output_format",
    type=click.Choice(["compact", "json"]),
    default="compact",
    help="Output format (default: compact for streaming)"
)
@click.option(
    "--progress/--no-progress", default=True,
    help="Show progress indicator"
)
@click.pass_context
def stream(
    ctx: click.Context,
    file: str,
    log_format: str,
    output_format: str,
    progress: bool,
) -> None:
    """
    Stream-parse very large log files (1-10GB+).

    Optimized for minimal memory usage. Requires format to be specified
    (no auto-detection) to avoid buffering.

    Examples:

    \b
        ulp stream --format docker_json huge-container.log
        ulp stream --format json app.log --output json
        ulp stream --format syslog_rfc3164 /var/log/messages --no-progress
    """
    from ulp.cli.commands import stream_command

    exit_code = stream_command(
        file_path=file,
        log_format=log_format,
        output_format=output_format,
        progress=progress,
        console=ctx.obj["console"],
        error_console=ctx.obj["error_console"],
    )
    ctx.exit(exit_code)


@cli.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
@click.option(
    "--all", "-a", "show_all", is_flag=True,
    help="Show all matching formats with confidence scores"
)
@click.pass_context
def detect(
    ctx: click.Context,
    files: tuple[str, ...],
    show_all: bool,
) -> None:
    """
    Detect the log format of files.

    Analyzes the content of each file and reports the detected format
    with a confidence score.

    Examples:

    \b
        ulp detect access.log
        ulp detect --all /var/log/*.log
    """
    from ulp.detection.detector import FormatDetector

    if not files:
        error_console.print("[red]Error:[/red] No files specified")
        ctx.exit(1)

    detector = FormatDetector()

    for file_path in files:
        try:
            path = Path(file_path)

            if show_all:
                # Show all matches
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    lines = [f.readline() for _ in range(50)]
                    lines = [line for line in lines if line.strip()]

                all_formats = detector.detect_all(lines)
                console.print(f"\n[bold]{path.name}[/bold]")

                for fmt, conf in all_formats[:5]:  # Top 5
                    bar = _confidence_bar(conf)
                    console.print(f"  {fmt:20} {bar} {conf:.0%}")
            else:
                # Show best match only
                fmt, conf = detector.detect_file(str(path))
                bar = _confidence_bar(conf)
                console.print(f"{path.name}: [cyan]{fmt}[/cyan] {bar} {conf:.0%}")

        except IOError as e:
            error_console.print(f"[red]Error reading {file_path}:[/red] {e}")


def _confidence_bar(confidence: float, width: int = 10) -> str:
    """Create a visual confidence bar."""
    filled = int(confidence * width)
    empty = width - filled

    if confidence >= 0.8:
        color = "green"
    elif confidence >= 0.5:
        color = "yellow"
    else:
        color = "red"

    return f"[{color}]{'█' * filled}{'░' * empty}[/{color}]"


@cli.command()
@click.pass_context
def formats(ctx: click.Context) -> None:
    """
    List all supported log formats.

    Shows all built-in parsers and the format names they handle.
    """
    from rich.table import Table
    from ulp.parsers import registry

    table = Table(title="Supported Log Formats")
    table.add_column("Parser", style="cyan")
    table.add_column("Formats", style="green")

    for parser_name in sorted(registry.list_parsers()):
        parser = registry.get_parser(parser_name)
        if parser:
            formats_str = ", ".join(parser.supported_formats)
            table.add_row(parser_name, formats_str)

    console.print(table)


if __name__ == "__main__":
    cli()
