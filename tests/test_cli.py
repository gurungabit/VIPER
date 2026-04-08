"""Tests for VIPER CLI."""

from pathlib import Path
from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from viper.cli import app
from viper.models.vulnerability import SnykReport

runner = CliRunner()


class TestCLI:
    def test_version(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "VIPER" in result.stdout

    def test_scan_with_report_file(self, npm_report_path: Path):
        result = runner.invoke(
            app, ["scan", "--report-file", str(npm_report_path)]
        )
        assert result.exit_code == 0
        assert "lodash" in result.stdout
        assert "axios" in result.stdout

    def test_scan_json_output(self, npm_report_path: Path):
        result = runner.invoke(
            app, ["scan", "--report-file", str(npm_report_path), "--output", "json"]
        )
        assert result.exit_code == 0

    def test_scan_severity_filter(self, npm_report_path: Path):
        result = runner.invoke(
            app,
            ["scan", "--report-file", str(npm_report_path), "--severity", "critical"],
        )
        assert result.exit_code == 0
        assert "axios" in result.stdout

    def test_scan_no_args(self):
        # Should fail without project-dir or report-file (no snyk installed in test env)
        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1

    def test_report_markdown(self, npm_report_path: Path):
        result = runner.invoke(
            app, ["report", "--report-file", str(npm_report_path)]
        )
        assert result.exit_code == 0
        assert "Vulnerability Report" in result.stdout

    def test_report_json(self, npm_report_path: Path):
        result = runner.invoke(
            app,
            ["report", "--report-file", str(npm_report_path), "--format", "json"],
        )
        assert result.exit_code == 0
        assert "vulnerabilities" in result.stdout

    def test_report_to_file(self, npm_report_path: Path, tmp_path: Path):
        output = tmp_path / "report.md"
        result = runner.invoke(
            app,
            [
                "report",
                "--report-file",
                str(npm_report_path),
                "--output",
                str(output),
            ],
        )
        assert result.exit_code == 0
        assert output.exists()
        assert "Vulnerability Report" in output.read_text()

    def test_auto_no_snyk(self):
        """auto command fails gracefully when snyk is not available."""
        result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])
        assert result.exit_code == 1

    def test_auto_clean_project(self):
        """auto command exits cleanly when scan returns no vulns."""
        empty_report = SnykReport(ok=True, vulnerabilities=[])
        with patch("viper.cli.SnykParser") as mock_parser:
            mock_parser.run_scan.return_value = empty_report
            mock_parser.filter_by_severity.return_value = []
            mock_parser.deduplicate.return_value = []
            result = runner.invoke(
                app, ["auto", "--project-dir", "/tmp"]
            )
            assert result.exit_code == 0
            assert "clean" in result.stdout.lower() or "No vulnerabilities" in result.stdout
