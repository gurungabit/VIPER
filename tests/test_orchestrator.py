"""Tests for the orchestrated remediation loop."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from viper.config import ViperConfig
from viper.models.result import AgentResult, FileChange
from viper.models.vulnerability import SnykReport
from viper.orchestrator import RemediationOrchestrator
from viper.parsers.snyk_parser import SnykParser


def _write_package_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _build_lodash_report() -> SnykReport:
    return SnykParser.parse_json(
        {
            "ok": False,
            "packageManager": "npm",
            "projectName": "my-project",
            "dependencyCount": 3,
            "displayTargetFile": "package.json",
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


class TestRemediationOrchestrator:
    def test_retries_same_batch_until_validation_clears_it(self, tmp_path: Path):
        _write_package_json(
            tmp_path / "package.json",
            '{\n  "name": "my-project",\n  "dependencies": {\n    "lodash": "^4.17.15"\n  }\n}\n',
        )

        vuln_report = _build_lodash_report()
        clean_report = SnykReport(ok=True, vulnerabilities=[], dependency_count=3)

        orchestrator = RemediationOrchestrator(
            config=ViperConfig(),
            project_dir=tmp_path,
            severity_threshold="high",
            max_cycles=5,
            use_ai=True,
            stream_agent=False,
            verbose=False,
        )

        with patch(
            "viper.orchestrator.SnykParser.run_scan",
            side_effect=[vuln_report, vuln_report, clean_report],
        ), patch.object(
            RemediationOrchestrator,
            "_run_agent_for_batch",
            side_effect=[
                AgentResult(
                    success=True,
                    summary="Attempted direct bump",
                    changes=[FileChange(path="package.json")],
                ),
                AgentResult(
                    success=True,
                    summary="Retried direct bump after validation feedback",
                    changes=[FileChange(path="package.json")],
                ),
            ],
        ) as run_agent:
            result = orchestrator.run()

        assert result.clean is True
        assert result.total_fixed >= 1
        assert result.cycles_completed == 1
        assert run_agent.call_count == 2

    def test_falls_back_to_batched_deterministic_fix(self, tmp_path: Path):
        _write_package_json(
            tmp_path / "package.json",
            '{\n  "name": "my-project",\n  "dependencies": {\n    "lodash": "^4.17.15"\n  }\n}\n',
        )

        vuln_report = _build_lodash_report()
        clean_report = SnykReport(ok=True, vulnerabilities=[], dependency_count=3)

        orchestrator = RemediationOrchestrator(
            config=ViperConfig(),
            project_dir=tmp_path,
            severity_threshold="high",
            max_cycles=5,
            use_ai=True,
            stream_agent=False,
            verbose=False,
        )

        fallback_result = AgentResult(
            success=True,
            summary="Upgraded 1 package:\n  [HIGH] lodash: 4.17.15 -> 4.17.21",
            changes=[FileChange(path="package.json")],
        )

        with patch(
            "viper.orchestrator.SnykParser.run_scan",
            side_effect=[vuln_report, clean_report],
        ), patch.object(
            RemediationOrchestrator,
            "_run_agent_for_batch",
            return_value=AgentResult(
                success=False,
                summary="Agent explored but made no changes",
                changes=[],
            ),
        ), patch(
            "viper.orchestrator.DirectFixer.fix_actions",
            return_value=fallback_result,
        ) as fix_actions:
            result = orchestrator.run()

        assert result.clean is True
        assert result.total_fixed >= 1
        fix_actions.assert_called_once()

    def test_stops_when_no_safe_actionable_units_exist(self, tmp_path: Path):
        _write_package_json(
            tmp_path / "package.json",
            '{\n  "name": "my-project",\n  "dependencies": {\n    "brace-expansion": "^2.0.2"\n  }\n}\n',
        )

        blocked_report = SnykParser.parse_json(
            {
                "ok": False,
                "packageManager": "npm",
                "projectName": "my-project",
                "displayTargetFile": "package.json",
                "dependencyCount": 3,
                "vulnerabilities": [
                    {
                        "id": "SNYK-JS-BRACEEXPANSION-1",
                        "title": "Infinite loop",
                        "severity": "high",
                        "packageName": "brace-expansion",
                        "version": "2.0.2",
                        "from": ["my-project@1.0.0", "brace-expansion@2.0.2"],
                        "upgradePath": [False, "brace-expansion@5.0.5"],
                        "isUpgradable": True,
                    }
                ],
            }
        )

        orchestrator = RemediationOrchestrator(
            config=ViperConfig(),
            project_dir=tmp_path,
            severity_threshold="high",
            max_cycles=5,
            use_ai=True,
            stream_agent=False,
            verbose=False,
        )

        with patch(
            "viper.orchestrator.SnykParser.run_scan",
            return_value=blocked_report,
        ), patch.object(
            RemediationOrchestrator,
            "_run_agent_for_batch",
        ) as run_agent:
            result = orchestrator.run()

        assert result.clean is False
        assert result.total_fixed == 0
        run_agent.assert_not_called()

    def test_groups_same_install_root_units_into_one_batch(self, tmp_path: Path):
        _write_package_json(
            tmp_path / "package.json",
            '{\n  "name": "my-project",\n  "private": true,\n  "dependencies": {\n    "express": "^5.0.0"\n  }\n}\n',
        )

        report = SnykParser.parse_json(
            {
                "ok": False,
                "packageManager": "npm",
                "projectName": "my-project",
                "displayTargetFile": "package-lock.json",
                "dependencyCount": 6,
                "vulnerabilities": [
                    {
                        "id": "SNYK-JS-LODASH-1",
                        "title": "Prototype Pollution",
                        "severity": "high",
                        "packageName": "lodash",
                        "version": "4.17.15",
                        "from": ["my-project@1.0.0", "express@5.0.0", "lodash@4.17.15"],
                        "upgradePath": [False, "express@5.0.0", "lodash@4.17.21"],
                        "isUpgradable": True,
                    },
                    {
                        "id": "SNYK-JS-FLATTED-1",
                        "title": "Prototype Pollution",
                        "severity": "critical",
                        "packageName": "flatted",
                        "version": "3.4.0",
                        "from": ["my-project@1.0.0", "eslint@9.0.0", "flatted@3.4.0"],
                        "upgradePath": [False, "eslint@9.0.0", "flatted@3.4.2"],
                        "isUpgradable": True,
                    },
                ],
            }
        )

        orchestrator = RemediationOrchestrator(
            config=ViperConfig(),
            project_dir=tmp_path,
            severity_threshold="high",
            max_cycles=5,
            use_ai=True,
            stream_agent=False,
            verbose=False,
        )

        units = orchestrator._plan_units(report)
        batches = orchestrator._plan_batches(units)

        assert len(units) == 2
        assert len(batches) == 1
        assert len(batches[0].actions) == 2
        assert batches[0].install_root == "."
