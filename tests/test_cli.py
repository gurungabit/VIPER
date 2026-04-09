"""Tests for VIPER CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from viper import ViperScanError
from viper.cli import app
from viper.orchestrator import AutoRunResult
from viper.models.vulnerability import SnykReport
from viper.parsers.snyk_parser import SnykParser

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
        with patch(
            "viper.orchestrator.RemediationOrchestrator.run",
            side_effect=ViperScanError("boom"),
        ):
            result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])
        assert result.exit_code == 1

    def test_auto_clean_project(self):
        """auto command exits cleanly when the orchestrator finishes without changes."""
        with patch(
            "viper.orchestrator.RemediationOrchestrator.run",
            return_value=AutoRunResult(
                cycles_completed=1,
                total_fixed=0,
                changes=[],
                clean=True,
                duration_seconds=0,
            ),
        ):
            result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])

        assert result.exit_code == 0
        assert "Summary" in result.stdout

    def test_auto_defaults_to_high_severity_and_streaming(self):
        """auto should default to high+ severity and live agent streaming."""
        captured: dict[str, object] = {}

        class FakeOrchestrator:
            def __init__(
                self,
                config,
                project_dir,
                severity_threshold,
                max_cycles,
                use_ai,
                stream_agent,
                verbose,
            ):
                captured["severity_threshold"] = severity_threshold
                captured["stream_agent"] = stream_agent
                captured["max_cycles"] = max_cycles
                captured["use_ai"] = use_ai

            def run(self):
                return AutoRunResult(
                    cycles_completed=1,
                    total_fixed=0,
                    changes=[],
                    clean=True,
                    duration_seconds=0,
                )

        with patch("viper.orchestrator.RemediationOrchestrator", FakeOrchestrator):
            result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])

        assert result.exit_code == 0
        assert captured["severity_threshold"] == "high"
        assert captured["stream_agent"] is True
        assert captured["max_cycles"] == 10
        assert captured["use_ai"] is True

    def test_auto_shows_orchestrated_loop_banner(self):
        with patch(
            "viper.orchestrator.RemediationOrchestrator.run",
            return_value=AutoRunResult(
                cycles_completed=1,
                total_fixed=1,
                changes=[],
                clean=True,
                duration_seconds=0,
            ),
        ):
            result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])

        assert result.exit_code == 0
        assert "orchestrated unit-by-unit loop" in result.stdout
        assert "Agent Steps: 40" in result.stdout

    def test_auto_can_disable_streaming(self):
        """auto should allow hiding live agent stream output."""
        captured: dict[str, object] = {}

        class FakeOrchestrator:
            def __init__(
                self,
                config,
                project_dir,
                severity_threshold,
                max_cycles,
                use_ai,
                stream_agent,
                verbose,
            ):
                captured["stream_agent"] = stream_agent

            def run(self):
                return AutoRunResult(
                    cycles_completed=1,
                    total_fixed=0,
                    changes=[],
                    clean=True,
                    duration_seconds=0,
                )

        with patch("viper.orchestrator.RemediationOrchestrator", FakeOrchestrator):
            result = runner.invoke(app, ["auto", "--project-dir", "/tmp", "--no-stream-agent"])

        assert result.exit_code == 0
        assert captured["stream_agent"] is False

    def test_auto_passes_agent_iteration_override(self):
        """auto should honor the per-run agent iteration override."""
        captured_iterations: list[int] = []

        class FakeOrchestrator:
            def __init__(
                self,
                config,
                project_dir,
                severity_threshold,
                max_cycles,
                use_ai,
                stream_agent,
                verbose,
            ):
                captured_iterations.append(config.agent.max_iterations)

            def run(self):
                return AutoRunResult(
                    cycles_completed=1,
                    total_fixed=0,
                    changes=[],
                    clean=True,
                    duration_seconds=0,
                )

        with patch("viper.orchestrator.RemediationOrchestrator", FakeOrchestrator):
            result = runner.invoke(
                app,
                ["auto", "--project-dir", "/tmp", "--agent-max-iterations", "60"],
            )

        assert result.exit_code == 0
        assert captured_iterations == [60]
        assert "Agent Steps: 60" in result.stdout
