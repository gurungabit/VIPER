"""Tests for VIPER CLI."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from viper.cli import app
from viper.models.result import AgentResult, FileChange
from viper.models.vulnerability import SnykReport
from viper.parsers.snyk_parser import SnykParser

runner = CliRunner()


class TestCLI:
    @staticmethod
    def _build_vuln_report() -> SnykReport:
        return SnykParser.parse_json(
            {
                "ok": False,
                "packageManager": "npm",
                "projectName": "my-project",
                "dependencyCount": 3,
                "vulnerabilities": [
                    {
                        "id": "SNYK-JS-LODASH-1",
                        "title": "Prototype Pollution",
                        "severity": "high",
                        "packageName": "lodash",
                        "version": "4.17.15",
                        "from": ["my-project@1.0.0", "lodash@4.17.15"],
                        "upgradePath": [False, "lodash@4.17.21"],
                        "isUpgradable": True,
                    }
                ],
            }
        )

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

    def test_auto_prefers_ai_agent_by_default(self):
        """auto should use the agent first and skip deterministic fallback when AI makes changes."""
        vuln_report = self._build_vuln_report()
        clean_report = SnykReport(ok=True, vulnerabilities=[], dependency_count=0)
        ai_result = AgentResult(
            success=True,
            summary="AI fixed lodash via direct bump",
            changes=[FileChange(path="package.json")],
        )

        with patch(
            "viper.cli.SnykParser.run_scan",
            side_effect=[vuln_report, clean_report],
        ), patch("viper.agent.loop.ViperAgent") as mock_agent_cls, patch(
            "viper.fixer.DirectFixer"
        ) as mock_fixer_cls:
            mock_agent = mock_agent_cls.return_value
            mock_agent.run_fix = AsyncMock(return_value=ai_result)

            result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])

        assert result.exit_code == 0
        assert "agent-first remediation loop" in result.stdout
        assert "AI fixed lodash" in result.stdout
        mock_fixer_cls.assert_not_called()

    def test_auto_falls_back_when_ai_makes_no_changes(self):
        """auto should fall back to the deterministic fixer when the AI agent makes no edits."""
        vuln_report = self._build_vuln_report()
        clean_report = SnykReport(ok=True, vulnerabilities=[], dependency_count=0)
        ai_result = AgentResult(
            success=False,
            summary="Could not determine the right manifest",
            changes=[],
        )
        fallback_result = AgentResult(
            success=True,
            summary="Upgraded 1 package:\n  [HIGH] lodash: 4.17.15 -> 4.17.21",
            changes=[FileChange(path="package.json")],
        )

        with patch(
            "viper.cli.SnykParser.run_scan",
            side_effect=[vuln_report, clean_report],
        ), patch("viper.agent.loop.ViperAgent") as mock_agent_cls, patch(
            "viper.fixer.DirectFixer"
        ) as mock_fixer_cls:
            mock_agent = mock_agent_cls.return_value
            mock_agent.run_fix = AsyncMock(return_value=ai_result)
            mock_fixer = mock_fixer_cls.return_value
            mock_fixer.fix.return_value = fallback_result

            result = runner.invoke(app, ["auto", "--project-dir", "/tmp"])

        assert result.exit_code == 0
        assert "falling back to deterministic version upgrades" in result.stdout.lower()
        mock_fixer_cls.assert_called_once()
