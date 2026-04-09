"""Regression tests for direct dependency remediation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from viper.fixer import DirectFixer
from viper.parsers.snyk_parser import SnykParser


def _write_json(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class TestDirectFixer:
    def test_plan_fixes_uses_nested_manifest_for_direct_dependency(self, tmp_path: Path):
        _write_json(
            tmp_path / "package.json",
            '{\n  "name": "root-app",\n  "private": true\n}\n',
        )
        _write_json(
            tmp_path / "client/package.json",
            '{\n  "name": "client-app",\n  "dependencies": {\n    "vite": "^8.0.0"\n  }\n}\n',
        )

        report = SnykParser.parse_json(
            [
                {
                    "ok": False,
                    "packageManager": "npm",
                    "projectName": "client-app",
                    "displayTargetFile": "client/package.json",
                    "vulnerabilities": [
                        {
                            "id": "SNYK-JS-VITE-1",
                            "title": "ReDoS",
                            "severity": "high",
                            "packageName": "vite",
                            "version": "8.0.0",
                            "from": ["client-app@1.0.0", "vite@8.0.0"],
                            "upgradePath": [False, "vite@8.0.7"],
                            "isUpgradable": True,
                        }
                    ],
                }
            ]
        )

        actions = DirectFixer(tmp_path)._plan_fixes(report)

        assert len(actions) == 1
        assert actions[0].file_path == "client/package.json"
        assert actions[0].is_direct is True

    def test_plan_fixes_uses_nested_manifest_for_transitive_override(self, tmp_path: Path):
        _write_json(
            tmp_path / "package.json",
            '{\n  "name": "root-app",\n  "private": true\n}\n',
        )
        _write_json(
            tmp_path / "client/package.json",
            '{\n  "name": "client-app",\n  "dependencies": {\n    "vite": "^8.0.0"\n  }\n}\n',
        )

        report = SnykParser.parse_json(
            [
                {
                    "ok": False,
                    "packageManager": "npm",
                    "projectName": "client-app",
                    "displayTargetFile": "client/package-lock.json",
                    "vulnerabilities": [
                        {
                            "id": "SNYK-JS-FASTXMLPARSER-1",
                            "title": "XML Entity Expansion",
                            "severity": "high",
                            "packageName": "fast-xml-parser",
                            "version": "5.4.1",
                            "from": [
                                "client-app@1.0.0",
                                "vite@8.0.0",
                                "fast-xml-parser@5.4.1",
                            ],
                            "upgradePath": [False, "vite@8.0.7", "fast-xml-parser@5.5.8"],
                            "isUpgradable": True,
                        }
                    ],
                }
            ]
        )

        actions = DirectFixer(tmp_path)._plan_fixes(report)

        assert len(actions) == 1
        assert actions[0].file_path == "client/package.json"
        assert actions[0].is_direct is False
        assert actions[0].fix_version == "5.5.8"

    def test_fix_refreshes_workspace_root_when_manifest_already_safe(self, tmp_path: Path):
        _write_json(
            tmp_path / "package.json",
            '{\n  "name": "root-app",\n  "private": true,\n  "workspaces": ["client"]\n}\n',
        )
        (tmp_path / "package-lock.json").write_text('{\n  "name": "root-app"\n}\n')
        _write_json(
            tmp_path / "client/package.json",
            '{\n  "name": "client-app",\n  "dependencies": {\n    "vite": "^8.0.7"\n  }\n}\n',
        )

        report = SnykParser.parse_json(
            [
                {
                    "ok": False,
                    "packageManager": "npm",
                    "projectName": "client-app",
                    "displayTargetFile": "client/package.json",
                    "vulnerabilities": [
                        {
                            "id": "SNYK-JS-VITE-1",
                            "title": "Auth Bypass",
                            "severity": "high",
                            "packageName": "vite",
                            "version": "8.0.0",
                            "from": ["client-app@1.0.0", "vite@8.0.0"],
                            "upgradePath": [False, "vite@8.0.7"],
                            "isUpgradable": True,
                        }
                    ],
                }
            ]
        )

        fixer = DirectFixer(tmp_path)
        completed = MagicMock(returncode=0, stdout="", stderr="")

        with patch("viper.fixer.subprocess.run", return_value=completed) as run_mock:
            result = fixer.fix(report)

        assert result.success is True
        assert "Refreshed install state" in result.summary
        assert result.changes == []
        run_mock.assert_called_once()
        assert run_mock.call_args.kwargs["cwd"] == tmp_path
