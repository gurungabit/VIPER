"""Parse and run Snyk vulnerability scans."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from viper import ViperParseError, ViperScanError
from viper.models.vulnerability import Severity, SnykReport, Vulnerability


class SnykParser:
    """Parse Snyk JSON reports and run scans."""

    @staticmethod
    def run_scan(
        project_dir: Path,
        snyk_token: str | None = None,
        org: str | None = None,
        severity_threshold: str | None = None,
    ) -> SnykReport:
        """Run `snyk test --json` and return parsed report."""
        cmd = ["snyk", "test", "--json"]
        if org:
            cmd.extend(["--org", org])
        if severity_threshold:
            cmd.extend(["--severity-threshold", severity_threshold])

        env = None
        if snyk_token:
            import os

            env = {**os.environ, "SNYK_TOKEN": snyk_token}

        try:
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=600,
                env=env,
            )
        except FileNotFoundError:
            raise ViperScanError(
                "Snyk CLI not found. Install it: npm install -g snyk"
            )
        except subprocess.TimeoutExpired:
            raise ViperScanError("Snyk scan timed out after 600 seconds")

        # Exit code 0 = no vulns, 1 = vulns found, 2+ = error
        if result.returncode >= 2:
            raise ViperScanError(f"Snyk scan failed (exit {result.returncode}): {result.stderr}")

        if not result.stdout.strip():
            raise ViperScanError("Snyk returned empty output")

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ViperParseError(f"Failed to parse Snyk JSON output: {e}")

        return SnykParser.parse_json(data)

    @staticmethod
    def parse_file(path: Path) -> SnykReport:
        """Parse an existing Snyk JSON report file."""
        try:
            raw = path.read_text()
        except FileNotFoundError:
            raise ViperParseError(f"Report file not found: {path}")

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ViperParseError(f"Invalid JSON in {path}: {e}")

        return SnykParser.parse_json(data)

    @staticmethod
    def parse_json(data: dict | list) -> SnykReport:
        """Parse raw JSON data into a SnykReport model."""
        # Snyk can return an array of reports (multi-project)
        if isinstance(data, list):
            if not data:
                return SnykReport()
            # Merge multiple reports
            all_vulns = []
            for item in data:
                report = SnykReport.model_validate(item)
                all_vulns.extend(report.vulnerabilities)
            merged = SnykReport.model_validate(data[0])
            merged.vulnerabilities = all_vulns
            return merged

        return SnykReport.model_validate(data)

    @staticmethod
    def filter_by_severity(
        report: SnykReport, min_severity: Severity
    ) -> list[Vulnerability]:
        """Return vulnerabilities at or above the given severity."""
        return [v for v in report.vulnerabilities if v.severity >= min_severity]

    @staticmethod
    def group_by_package(
        vulns: list[Vulnerability],
    ) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by package name."""
        groups: dict[str, list[Vulnerability]] = {}
        for v in vulns:
            groups.setdefault(v.package_name, []).append(v)
        return groups

    @staticmethod
    def deduplicate(vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Remove duplicate vulnerabilities by ID."""
        seen: set[str] = set()
        unique = []
        for v in vulns:
            if v.id not in seen:
                seen.add(v.id)
                unique.append(v)
        return unique
