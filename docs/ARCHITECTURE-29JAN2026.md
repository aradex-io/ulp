# Architecture Overview

**Last Updated:** January 29, 2026

This document describes the architectural design of Universal Log Parser (ULP), which follows Clean Architecture principles with Domain-Driven Design.

## Table of Contents

- [Architectural Principles](#architectural-principles)
- [Layer Structure](#layer-structure)
- [Dependency Flow](#dependency-flow)
- [Core Concepts](#core-concepts)
- [Design Patterns](#design-patterns)
- [Extension Points](#extension-points)

---

## Architectural Principles

ULP is built on these foundational principles:

### 1. Clean Architecture (Hexagonal Architecture)

The codebase is organized into concentric layers with **dependencies pointing inward**:

```
┌─────────────────────────────────────────┐
│     Infrastructure (Adapters)           │  ← External concerns
│  ┌───────────────────────────────────┐  │
│  │   Application (Use Cases)         │  │  ← Business orchestration
│  │  ┌─────────────────────────────┐  │  │
│  │  │   Domain (Entities)         │  │  │  ← Business rules
│  │  │                             │  │  │
│  │  └─────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Benefits:**
- Business logic independent of frameworks
- Testable without infrastructure
- Swappable adapters (e.g., different file sources)
- Clear separation of concerns

### 2. Domain-Driven Design (DDD)

Core business concepts are modeled as domain entities:

- **Entities**: `LogEntry`, `CorrelationGroup`
- **Value Objects**: `LogLevel`, `LogSource`, `HTTPInfo`
- **Services**: `CorrelationStrategy`, `NormalizationStep`
- **Aggregates**: `CorrelationResult` (aggregate of groups)

### 3. Dependency Inversion

High-level policies don't depend on low-level details. Instead:

- Application layer defines **ports** (interfaces)
- Infrastructure layer provides **adapters** (implementations)
- Domain layer has **zero external dependencies**

### 4. Single Responsibility

Each module has one reason to change:

- **Parsers**: Format-specific parsing logic
- **Detection**: Format identification
- **Correlation**: Log grouping strategies
- **Normalization**: Data transformation
- **CLI**: User interface

---

## Layer Structure

### Directory Layout

```
src/ulp/
├── __init__.py              # Public API exports
├── domain/                  # Core business logic (no dependencies)
│   ├── entities.py          # LogEntry, CorrelationGroup, CorrelationResult
│   └── services.py          # CorrelationStrategy, NormalizationStep protocols
├── application/             # Use cases (orchestration)
│   ├── parse_logs.py        # ParseLogsUseCase, ParseLogsStreamingUseCase
│   ├── correlate_logs.py    # CorrelateLogsUseCase
│   └── ports.py             # Port interfaces (FormatDetectorPort, etc.)
├── infrastructure/          # Adapters (external implementations)
│   ├── sources/             # File, stdin, mmap sources
│   │   ├── file_source.py
│   │   └── stdin_source.py
│   ├── correlation/         # Correlation strategies
│   │   └── strategies.py
│   ├── normalization/       # Normalization pipeline
│   │   ├── pipeline.py
│   │   └── steps.py
│   └── adapters/            # Port implementations
│       ├── detection.py
│       └── parser_registry.py
├── parsers/                 # Format-specific parsers
│   ├── __init__.py          # ParserRegistry
│   ├── json_parser.py
│   ├── nginx.py
│   ├── apache.py
│   ├── syslog.py
│   ├── docker.py
│   ├── kubernetes.py
│   ├── python_logging.py
│   └── generic.py
├── detection/               # Format auto-detection
│   ├── detector.py          # FormatDetector
│   └── signatures.py        # Format signatures
├── core/                    # Shared core (legacy, being migrated to domain)
│   ├── models.py            # Core models (LogEntry, etc.)
│   ├── base.py              # BaseParser
│   └── exceptions.py        # ULPError, ParseError, etc.
└── cli/                     # Command-line interface
    ├── main.py              # Click commands
    ├── commands.py          # Command implementations
    └── output.py            # Rich output formatting
```

---

## Layer Details

### Domain Layer

**Purpose:** Contains pure business logic and entities

**Rules:**
- **No external dependencies** (no imports from other layers)
- **No I/O operations** (no file access, network calls)
- **Pure functions** where possible
- **Immutable value objects**

**Key Files:**

#### `domain/entities.py`

Core business entities representing the domain model:

```python
@dataclass
class LogEntry:
    """Universal log entry - the heart of ULP."""
    timestamp: datetime | None
    level: LogLevel
    message: str
    source: LogSource
    correlation: CorrelationIds
    # ... other fields

@dataclass
class CorrelationGroup:
    """Group of related log entries."""
    correlation_key: str
    correlation_type: str
    entries: list[LogEntry]
    time_range: tuple[datetime, datetime] | None

@dataclass
class CorrelationResult:
    """Result of correlation operation."""
    groups: list[CorrelationGroup]
    orphan_entries: list[LogEntry]
    statistics: dict[str, Any]
```

#### `domain/services.py`

Domain service protocols (interfaces):

```python
class CorrelationStrategy(Protocol):
    """Interface for correlation strategies."""
    @property
    def name(self) -> str: ...

    def correlate(
        self,
        entries: Iterator[LogEntry],
        buffer_size: int = 10000
    ) -> Iterator[CorrelationGroup]: ...

class NormalizationStep(Protocol):
    """Interface for normalization steps."""
    def normalize(self, entry: LogEntry) -> LogEntry: ...
```

**Design:** Uses Python protocols (structural subtyping) rather than abstract base classes for flexibility.

---

### Application Layer

**Purpose:** Orchestrates domain objects to fulfill use cases

**Rules:**
- Defines **ports** (interfaces for infrastructure)
- Implements **use cases** (business workflows)
- **No framework dependencies** (except for typing)
- Coordinates domain entities

**Key Files:**

#### `application/ports.py`

Port interfaces for infrastructure:

```python
class LogSourcePort(Protocol):
    """Port for reading log data."""
    def read_lines(self) -> Iterator[str]: ...
    def metadata(self) -> dict[str, str]: ...

class ParserRegistryPort(Protocol):
    """Port for accessing parsers."""
    def get_parser(self, format_name: str) -> BaseParser | None: ...

class FormatDetectorPort(Protocol):
    """Port for format detection."""
    def detect(self, sample: list[str]) -> tuple[str, float]: ...

class NormalizerPort(Protocol):
    """Port for normalization."""
    def process(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]: ...
```

#### `application/parse_logs.py`

Use cases for log parsing:

```python
class ParseLogsUseCase:
    """Use case: Parse logs from a source."""

    def __init__(
        self,
        source: LogSourcePort,
        parser_registry: ParserRegistryPort,
        format_detector: FormatDetectorPort | None = None,
        normalizer: NormalizerPort | None = None,
    ):
        self.source = source
        self.parser_registry = parser_registry
        self.format_detector = format_detector
        self.normalizer = normalizer

    def execute(
        self,
        format_hint: str | None = None
    ) -> Iterator[LogEntry]:
        """Execute the use case."""
        # 1. Detect format if not provided
        # 2. Get appropriate parser
        # 3. Parse lines
        # 4. Normalize if requested
        # 5. Yield entries
```

#### `application/correlate_logs.py`

Use case for log correlation:

```python
class CorrelateLogsUseCase:
    """Use case: Correlate logs across sources."""

    def __init__(
        self,
        strategies: list[CorrelationStrategy],
        window_size: int = 10000
    ):
        self.strategies = strategies
        self.window_size = window_size

    def execute(
        self,
        entry_iterators: list[Iterator[LogEntry]]
    ) -> CorrelationResult:
        """Execute correlation across multiple sources."""
        # 1. Merge iterators
        # 2. Apply strategies
        # 3. Collect groups
        # 4. Return result
```

**Pattern:** Use cases are the **only entry points** to the application layer. They orchestrate domain entities using infrastructure adapters.

---

### Infrastructure Layer

**Purpose:** Implements adapters for external systems

**Rules:**
- Implements **port interfaces** from application layer
- Contains all **I/O operations** (files, network, etc.)
- Can depend on external libraries
- Swappable implementations

**Key Adapters:**

#### Sources (`infrastructure/sources/`)

Implementations of `LogSourcePort`:

```python
class FileStreamSource:
    """Standard file reading."""
    def read_lines(self) -> Iterator[str]:
        with open(self.path) as f:
            for line in f:
                yield line.rstrip()

class LargeFileStreamSource:
    """Memory-mapped I/O for large files."""
    def read_lines(self) -> Iterator[str]:
        # Uses mmap for >100MB files
        # Efficient for 1-10GB+ files

class StdinStreamSource:
    """Read from standard input."""
    def read_lines(self) -> Iterator[str]:
        for line in sys.stdin:
            yield line.rstrip()
```

#### Correlation Strategies (`infrastructure/correlation/`)

Implementations of `CorrelationStrategy`:

```python
class RequestIdCorrelation(CorrelationStrategy):
    """Correlate by request/trace/correlation ID."""
    def correlate(self, entries) -> Iterator[CorrelationGroup]:
        # Group by ID fields
        # Emit groups

class TimestampWindowCorrelation(CorrelationStrategy):
    """Correlate by temporal proximity."""
    def correlate(self, entries) -> Iterator[CorrelationGroup]:
        # Group by time window
        # Emit groups

class SessionCorrelation(CorrelationStrategy):
    """Correlate by session/user ID."""
    def correlate(self, entries) -> Iterator[CorrelationGroup]:
        # Track sessions
        # Handle timeouts
        # Emit groups
```

#### Normalization (`infrastructure/normalization/`)

Implementations of `NormalizationStep`:

```python
class TimestampNormalizer(NormalizationStep):
    """Normalize timestamps to target timezone."""
    def normalize(self, entry: LogEntry) -> LogEntry:
        # Convert timestamp to UTC
        # Return new entry

class LevelNormalizer(NormalizationStep):
    """Standardize log levels."""
    def normalize(self, entry: LogEntry) -> LogEntry:
        # Map level variants
        # Return new entry
```

**Pipeline Pattern:**

```python
class NormalizationPipeline:
    """Chain of responsibility for normalization."""
    def __init__(self, steps: list[NormalizationStep]):
        self.steps = steps

    def process(self, entries: Iterator[LogEntry]) -> Iterator[LogEntry]:
        for entry in entries:
            result = entry
            for step in self.steps:
                result = step.normalize(result)
            yield result
```

---

### Parsers Layer

**Purpose:** Format-specific parsing logic

**Pattern:** Strategy pattern - each parser is a strategy for parsing a specific format

**Base Class:**

```python
class BaseParser(ABC):
    """Base class for all parsers."""

    name: str
    supported_formats: list[str]

    @abstractmethod
    def parse_line(self, line: str) -> LogEntry:
        """Parse a single line."""
        pass

    @abstractmethod
    def can_parse(self, sample: list[str]) -> float:
        """Return confidence (0.0-1.0) for sample."""
        pass

    def parse_stream(self, lines: Iterator[str]) -> Iterator[LogEntry]:
        """Parse a stream of lines (default: line-by-line)."""
        for line in lines:
            yield self.parse_line(line)
```

**Example Parser:**

```python
class NginxAccessParser(BaseParser):
    name = "nginx_access"
    supported_formats = ["nginx_access", "nginx_default", "nginx"]

    PATTERN = re.compile(r'^(?P<ip>\S+) .* "(?P<request>.*)" (?P<status>\d+) ...')

    def parse_line(self, line: str) -> LogEntry:
        match = self.PATTERN.match(line)
        if not match:
            return self._create_error_entry(line, "No match")

        return LogEntry(
            raw=line,
            timestamp=self._parse_timestamp(match.group('timestamp')),
            level=self._level_from_status(match.group('status')),
            message=f"{match.group('request')} -> {match.group('status')}",
            http=HTTPInfo(status_code=int(match.group('status'))),
            network=NetworkInfo(source_ip=match.group('ip')),
        )

    def can_parse(self, sample: list[str]) -> float:
        matches = sum(1 for line in sample if self.PATTERN.match(line))
        return matches / len(sample)
```

**Registry Pattern:**

```python
class ParserRegistry:
    """Central registry for all parsers."""

    def __init__(self):
        self._parsers: dict[str, Type[BaseParser]] = {}
        self._format_to_parser: dict[str, str] = {}

    def register(self, parser_class: Type[BaseParser]) -> None:
        instance = parser_class()
        self._parsers[instance.name] = parser_class
        for fmt in instance.supported_formats:
            self._format_to_parser[fmt] = instance.name

    def get_parser(self, format_name: str) -> BaseParser | None:
        parser_class = self._parsers.get(format_name)
        return parser_class() if parser_class else None
```

---

### Detection Layer

**Purpose:** Auto-detect log formats

**Strategy:** Multi-stage detection pipeline

```python
class FormatDetector:
    """Detect log format from sample lines."""

    def detect(self, sample: list[str]) -> tuple[str, float]:
        """Detect format with confidence score."""

        # Stage 1: Check for JSON
        if self._is_json(sample):
            return ("json_structured", 1.0)

        # Stage 2: Try parsers
        best_parser = None
        best_confidence = 0.0

        for parser_class in registry.list_parsers():
            parser = parser_class()
            confidence = parser.can_parse(sample)
            if confidence > best_confidence:
                best_confidence = confidence
                best_parser = parser.name

        # Stage 3: Fallback to generic
        if best_confidence < 0.3:
            return ("generic", 0.3)

        return (best_parser, best_confidence)
```

---

### CLI Layer

**Purpose:** Command-line interface

**Pattern:** Command pattern with Click framework

**Structure:**

```python
# main.py - CLI definitions
@click.group()
def cli():
    """ULP - Universal Log Parser"""
    pass

@cli.command()
@click.argument("files", nargs=-1)
@click.option("--format", "-f")
def parse(files, format):
    """Parse log files."""
    from ulp.cli.commands import parse_command
    exit_code = parse_command(files, format, ...)
    sys.exit(exit_code)

# commands.py - Command implementations
def parse_command(files, format, ...) -> int:
    """Execute parse command using application layer."""

    # Create adapters
    detector = FormatDetectorAdapter()
    registry = ParserRegistryAdapter()

    # Create use case
    source = FileStreamSource(files[0])
    use_case = ParseLogsUseCase(
        source=source,
        parser_registry=registry,
        format_detector=detector,
    )

    # Execute
    for entry in use_case.execute(format_hint=format):
        render_entry(entry)

    return 0
```

---

## Dependency Flow

Dependencies **always point inward**:

```
CLI → Application → Domain ← Infrastructure
 ↓         ↓          ↑            ↓
 └─────────┴──────────┴────────────┘
          Uses ports/adapters
```

**Example Flow:**

1. **CLI** receives user command
2. **CLI** creates **Infrastructure** adapters (file source, registry)
3. **CLI** creates **Application** use case with adapters
4. **Use case** orchestrates **Domain** entities
5. **Use case** calls **Infrastructure** through ports
6. **CLI** renders output

**No circular dependencies:**
- Domain never imports from Application or Infrastructure
- Application defines ports, doesn't import Infrastructure
- Infrastructure implements ports, imports from Application/Domain

---

## Design Patterns

### Strategy Pattern

**Used for:** Parsers, Correlation strategies, Normalization steps

```python
# Strategy interface
class CorrelationStrategy(Protocol):
    def correlate(self, entries) -> Iterator[CorrelationGroup]: ...

# Concrete strategies
class RequestIdCorrelation(CorrelationStrategy): ...
class TimestampWindowCorrelation(CorrelationStrategy): ...

# Context uses strategies
class CorrelateLogsUseCase:
    def __init__(self, strategies: list[CorrelationStrategy]):
        self.strategies = strategies
```

### Registry Pattern

**Used for:** Parser management

```python
registry = ParserRegistry()
registry.register(NginxAccessParser)
registry.register(ApacheCommonParser)

parser = registry.get_parser("nginx_access")
```

### Factory Pattern

**Used for:** LogEntry creation

```python
class BaseParser:
    def parse_line(self, line: str) -> LogEntry:
        # Factory method creates appropriate LogEntry
        return LogEntry(...)
```

### Chain of Responsibility

**Used for:** Normalization pipeline

```python
pipeline = NormalizationPipeline([
    TimestampNormalizer(),
    LevelNormalizer(),
    FieldNormalizer(),
])

for entry in pipeline.process(entries):
    # Entry has passed through all steps
```

### Adapter Pattern

**Used for:** Infrastructure implementations

```python
# Port (interface)
class LogSourcePort(Protocol):
    def read_lines(self) -> Iterator[str]: ...

# Adapter (implementation)
class FileStreamSource:
    def read_lines(self) -> Iterator[str]:
        # Adapts file I/O to port interface
```

### Iterator Pattern

**Used for:** Streaming, lazy evaluation

```python
def stream_parse(file_path, format):
    """Generator function for streaming."""
    source = LargeFileStreamSource(file_path)
    parser = registry.get_parser(format)

    for line in source.read_lines():  # Iterator
        yield parser.parse_line(line)  # Generator
```

---

## Extension Points

### Adding a Custom Parser

1. Subclass `BaseParser`
2. Implement `parse_line()` and `can_parse()`
3. Register with registry

```python
from ulp.core.base import BaseParser
from ulp.parsers import registry

class MyCustomParser(BaseParser):
    name = "my_format"
    supported_formats = ["my_format", "custom"]

    def parse_line(self, line: str) -> LogEntry:
        # Parse logic
        return LogEntry(...)

    def can_parse(self, sample: list[str]) -> float:
        # Detection logic
        return 0.9

registry.register(MyCustomParser)
```

### Adding a Correlation Strategy

1. Implement `CorrelationStrategy` protocol
2. Use in `correlate()` function

```python
from ulp.domain.services import CorrelationStrategy

class CustomCorrelation(CorrelationStrategy):
    @property
    def name(self) -> str:
        return "custom"

    def correlate(self, entries, buffer_size=10000):
        # Correlation logic
        yield CorrelationGroup(...)

# Use it
from ulp import correlate
correlate(["app.log"], strategy=CustomCorrelation())
```

### Adding a Normalization Step

1. Implement `NormalizationStep` protocol
2. Add to pipeline

```python
from ulp.domain.services import NormalizationStep

class CustomNormalizer(NormalizationStep):
    def normalize(self, entry: LogEntry) -> LogEntry:
        # Transformation logic
        return modified_entry

pipeline = NormalizationPipeline([
    CustomNormalizer(),
    TimestampNormalizer(),
])
```

---

## Testing Strategy

### Unit Tests

- **Domain**: Pure unit tests (no mocks needed)
- **Application**: Test use cases with mock adapters
- **Infrastructure**: Integration tests with real I/O
- **Parsers**: Sample-based tests

```python
# Domain test (no mocks)
def test_correlation_group_timeline():
    entries = [create_entry(ts="10:00"), create_entry(ts="09:00")]
    group = CorrelationGroup(entries=entries)
    timeline = group.timeline()
    assert timeline[0].timestamp < timeline[1].timestamp

# Application test (with mocks)
def test_parse_use_case():
    mock_source = Mock(spec=LogSourcePort)
    mock_source.read_lines.return_value = iter(["line1", "line2"])

    use_case = ParseLogsUseCase(source=mock_source, ...)
    entries = list(use_case.execute())

    assert len(entries) == 2

# Parser test (sample-based)
def test_nginx_parser():
    parser = NginxAccessParser()
    line = '192.168.1.1 - - [29/Jan/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 612'
    entry = parser.parse_line(line)

    assert entry.network.source_ip == "192.168.1.1"
    assert entry.http.status_code == 200
```

---

## Performance Characteristics

### Memory Usage

- **Regular parse**: O(n) - loads all entries
- **Stream parse**: O(1) - constant memory
- **Correlation**: O(k) - buffer size (default 10,000)

### Time Complexity

- **Parsing**: O(n) - linear in lines
- **Detection**: O(m) - sample size (typically 50 lines)
- **Correlation**: O(n log n) - sorting for timestamp correlation

### Streaming Performance

- Standard: ~50,000-100,000 lines/sec
- Memory-mapped: ~100,000-200,000 lines/sec
- Memory: ~10-20MB regardless of file size

---

## Future Enhancements

Potential architectural improvements:

1. **Plugin System**: Dynamic parser loading
2. **Async I/O**: Concurrent file reading
3. **Batch Processing**: Parallel correlation
4. **Caching Layer**: Memoize detection results
5. **Event Sourcing**: Audit log of parse operations

---

## Next Steps

- [Design Principles](DESIGN-PRINCIPLES-29JAN2026.md)
- [Extension Guide](EXTENSIONS-29JAN2026.md)
- [Parser Reference](reference/PARSERS-29JAN2026.md)
