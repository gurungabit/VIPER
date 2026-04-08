"""Tests for VIPER CLI."""

from pathlib import Path

from typer.testing import CliRunner

from viper.cli import app

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
