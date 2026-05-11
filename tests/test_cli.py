"""
Tests for CLI interface.
"""

import pytest
from click.testing import CliRunner

from ulp.cli.main import cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestCLI:
    """Tests for CLI commands."""

    def test_cli_version(self, runner):
        """Test --version flag."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.2.0" in result.output

    def test_cli_help(self, runner):
        """Test --help flag."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ULP - Universal Log Parser" in result.output
        assert "parse" in result.output
        assert "detect" in result.output

    def test_parse_help(self, runner):
        """Test parse --help."""
        result = runner.invoke(cli, ["parse", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--output" in result.output
        assert "--level" in result.output

    def test_detect_help(self, runner):
        """Test detect --help."""
        result = runner.invoke(cli, ["detect", "--help"])
        assert result.exit_code == 0
        assert "--all" in result.output

    def test_formats_command(self, runner):
        """Test formats command."""
        result = runner.invoke(cli, ["formats"])
        assert result.exit_code == 0
        assert "json" in result.output
        assert "apache" in result.output


class TestParseCommand:
    """Tests for parse command."""

    def test_parse_json_file(self, runner, tmp_path):
        """Test parsing a JSON log file."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            '{"timestamp": "2026-01-27T10:00:00Z", "level": "INFO", "message": "Test1"}\n'
            '{"timestamp": "2026-01-27T10:00:01Z", "level": "ERROR", "message": "Test2"}\n'
        )

        result = runner.invoke(cli, ["parse", str(log_file)])
        assert result.exit_code == 0
        assert "INFO" in result.output
        assert "ERROR" in result.output

    def test_parse_with_format(self, runner, tmp_path):
        """Test parsing with explicit format."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"level": "INFO", "message": "Test"}\n')

        result = runner.invoke(cli, ["parse", "--format", "json_structured", str(log_file)])
        assert result.exit_code == 0

    def test_parse_json_output(self, runner, tmp_path):
        """Test parsing with JSON output."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"level": "INFO", "message": "Test"}\n')

        result = runner.invoke(cli, ["parse", "--output", "json", str(log_file)])
        assert result.exit_code == 0
        assert '"level": "INFO"' in result.output

    def test_parse_csv_output(self, runner, tmp_path):
        """Test parsing with CSV output."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"level": "INFO", "message": "Test"}\n')

        result = runner.invoke(cli, ["parse", "--output", "csv", str(log_file)])
        assert result.exit_code == 0
        assert "timestamp" in result.output
        assert "level" in result.output

    def test_parse_compact_output(self, runner, tmp_path):
        """Test parsing with compact output."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"timestamp": "2026-01-27T10:00:00Z", "level": "INFO", "message": "Test"}\n')

        result = runner.invoke(cli, ["parse", "--output", "compact", str(log_file)])
        assert result.exit_code == 0
        assert "INFO" in result.output

    def test_parse_level_filter(self, runner, tmp_path):
        """Test parsing with level filter."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            '{"level": "DEBUG", "message": "Debug"}\n'
            '{"level": "INFO", "message": "Info"}\n'
            '{"level": "ERROR", "message": "Error"}\n'
        )

        result = runner.invoke(cli, ["parse", "--level", "error", str(log_file)])
        assert result.exit_code == 0
        assert "Error" in result.output
        # Debug and Info should be filtered out
        assert "Debug" not in result.output

    def test_parse_limit(self, runner, tmp_path):
        """Test parsing with limit."""
        log_file = tmp_path / "test.log"
        lines = [f'{{"level": "INFO", "message": "Line {i}"}}\n' for i in range(10)]
        log_file.write_text("".join(lines))

        result = runner.invoke(cli, ["parse", "--limit", "3", str(log_file)])
        assert result.exit_code == 0
        assert "Line 0" in result.output
        assert "Line 9" not in result.output

    def test_parse_grep(self, runner, tmp_path):
        """Test parsing with grep filter."""
        log_file = tmp_path / "test.log"
        log_file.write_text(
            '{"level": "INFO", "message": "User logged in"}\n'
            '{"level": "INFO", "message": "File downloaded"}\n'
            '{"level": "ERROR", "message": "User authentication failed"}\n'
        )

        result = runner.invoke(cli, ["parse", "--grep", "User", str(log_file)])
        assert result.exit_code == 0
        assert "User" in result.output
        assert "File downloaded" not in result.output

    def test_parse_nonexistent_file(self, runner):
        """Test parsing non-existent file."""
        result = runner.invoke(cli, ["parse", "/nonexistent/file.log"])
        assert result.exit_code != 0

    def test_parse_no_files(self, runner):
        """Test parse with no files and no stdin."""
        result = runner.invoke(cli, ["parse"])
        # CliRunner simulates empty stdin, which is processed as empty input
        # Accept either "No input", "No files", or "No matching" as valid responses
        assert ("No input" in result.output or
                "No files" in result.output or
                "No matching" in result.output)


class TestDetectCommand:
    """Tests for detect command."""

    def test_detect_json(self, runner, tmp_path):
        """Test detecting JSON format."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"level": "INFO", "message": "Test"}\n' * 5)

        result = runner.invoke(cli, ["detect", str(log_file)])
        assert result.exit_code == 0
        assert "json" in result.output.lower()

    def test_detect_apache(self, runner, tmp_path):
        """Test detecting Apache format."""
        log_file = tmp_path / "access.log"
        log_file.write_text(
            '192.168.1.1 - - [27/Jan/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"\n' * 5
        )

        result = runner.invoke(cli, ["detect", str(log_file)])
        assert result.exit_code == 0
        # Should detect as apache_combined or nginx_access (similar formats)
        assert "apache" in result.output.lower() or "nginx" in result.output.lower()

    def test_detect_all_flag(self, runner, tmp_path):
        """Test detect --all flag."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"level": "INFO", "message": "Test"}\n' * 5)

        result = runner.invoke(cli, ["detect", "--all", str(log_file)])
        assert result.exit_code == 0
        # Should show multiple formats with confidence scores
        assert "%" in result.output

    def test_detect_no_files(self, runner):
        """Test detect with no files."""
        result = runner.invoke(cli, ["detect"])
        assert result.exit_code != 0
        assert "No files specified" in result.output


class TestQuietMode:
    """Tests for quiet mode."""

    def test_quiet_parse(self, runner, tmp_path):
        """Test parse with --quiet flag."""
        log_file = tmp_path / "test.log"
        log_file.write_text('{"level": "INFO", "message": "Test"}\n')

        result = runner.invoke(cli, ["--quiet", "parse", str(log_file)])
        assert result.exit_code == 0
        # Should not show detection info
        assert "Detected" not in result.output
