"""Parse and run Snyk vulnerability scans."""

from __future__ import annotations

import json
import os
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
    ) -> SnykReport:
        """Run `snyk test --json` and return parsed report."""
        cmd = [
            "snyk", "test", "--json", "--dev",
            "--all-projects", "--detection-depth=4",
            "--exclude=node_modules,.venv,venv,__pycache__,.git,.tox,.eggs,.terraform,vendor",
        ]
        # NOTE: --severity-threshold is NOT passed to Snyk because some CLI
        # versions reject it. We fetch all vulns and filter on our side.
        if org:
            cmd.extend(["--org", org])

        # Build env: always inherit parent env so SNYK_TOKEN from shell works.
        # Only override if an explicit token is provided via config.
        env = {**os.environ}
        if snyk_token:
            env["SNYK_TOKEN"] = snyk_token

        # Check SNYK_TOKEN is available
        if not env.get("SNYK_TOKEN"):
            raise ViperScanError(
                "SNYK_TOKEN not set. Either:\n"
                "  1. Set the SNYK_TOKEN environment variable: export SNYK_TOKEN=<token>\n"
                "  2. Run `snyk auth` to authenticate interactively\n"
                "  3. Add snyk.token to viper.yaml (run `viper init` to create one)"
            )

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

        # Try to parse JSON from stdout even on error — snyk puts error details there
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                data = None
        else:
            data = None

        # Exit code 0 = no vulns, 1 = vulns found, 2 = action needed, 3 = no supported files
        if result.returncode >= 2:
            # Extract useful error message from JSON if available
            error_msg = ""
            if isinstance(data, dict):
                error_msg = data.get("error", "") or data.get("message", "")
            if not error_msg:
                error_msg = result.stderr.strip() or result.stdout.strip()

            # Provide actionable hints for common errors
            hint = ""
            if result.returncode == 3 or "no supported" in error_msg.lower():
                hint = "\nHint: No supported manifest files found. Make sure the project directory contains package.json, requirements.txt, pom.xml, etc."
            elif "auth" in error_msg.lower() or "unauthorized" in error_msg.lower():
                hint = "\nHint: Authentication failed. Check your SNYK_TOKEN or run `snyk auth`."
            elif "could not detect" in error_msg.lower():
                hint = "\nHint: Snyk couldn't detect the project type. Ensure you're pointing at a directory with dependency files."

            raise ViperScanError(
                f"Snyk scan failed (exit {result.returncode}): {error_msg}{hint}"
            )

        if data is None:
            raise ViperScanError("Snyk returned empty output")

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
