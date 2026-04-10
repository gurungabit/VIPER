"""Parse and run Snyk Code (SAST) scans."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from viper import ViperParseError, ViperScanError
from viper.models.code_issue import (
    SARIF_LEVEL_MAP,
    CodeFlowStep,
    CodeIssue,
    CodeReport,
)
from viper.models.vulnerability import Severity


class SnykCodeParser:
    """Parse Snyk Code SARIF reports and run SAST scans."""

    @staticmethod
    def run_code_scan(
        project_dir: Path,
        snyk_token: str | None = None,
        org: str | None = None,
    ) -> CodeReport:
        """Run `snyk code test --json` and return parsed SARIF report."""
        cmd = ["snyk", "code", "test", "--json"]
        if org:
            cmd.extend(["--org", org])

        env = {**os.environ}
        if snyk_token:
            env["SNYK_TOKEN"] = snyk_token

        # Check authentication
        snyk_oauth_config = Path.home() / ".config" / "configstore" / "snyk.json"
        has_oauth = snyk_oauth_config.exists()
        if not env.get("SNYK_TOKEN") and not has_oauth:
            raise ViperScanError(
                "SNYK_TOKEN not set. Either:\n"
                "  1. Set the SNYK_TOKEN environment variable\n"
                "  2. Run `snyk auth` to authenticate\n"
                "  3. Add snyk.token to viper.yaml"
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
            raise ViperScanError("Snyk CLI not found. Install it: npm install -g snyk")
        except subprocess.TimeoutExpired:
            raise ViperScanError("Snyk code scan timed out after 600 seconds")

        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                if result.returncode >= 2:
                    raise ViperScanError(
                        f"Snyk code scan failed (exit {result.returncode}): "
                        f"{result.stdout[:300]}"
                    )
                raise ViperParseError("Failed to parse Snyk Code JSON output")

            # Check for API errors
            if isinstance(data, dict) and data.get("error"):
                raise ViperScanError(
                    f"Snyk code scan failed: {data['error']}"
                )

            return SnykCodeParser.parse_sarif(data)

        if result.returncode == 0:
            return CodeReport(ok=True)

        stderr = result.stderr.strip()[:300] if result.stderr else "unknown error"
        raise ViperScanError(
            f"Snyk code scan failed (exit {result.returncode}): {stderr}"
        )

    @staticmethod
    def parse_file(path: Path) -> CodeReport:
        """Parse an existing Snyk Code SARIF JSON report file."""
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            raise ViperParseError(f"Failed to read code report: {e}")
        return SnykCodeParser.parse_sarif(data)

    @staticmethod
    def parse_sarif(data: dict) -> CodeReport:
        """Parse SARIF JSON structure into CodeReport."""
        runs = data.get("runs", [])
        if not runs:
            return CodeReport(ok=True)

        run = runs[0]

        # Extract tool info
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", "SnykCode")
        tool_version = driver.get("semanticVersion", driver.get("version", ""))

        # Build rule lookup for names
        rules = driver.get("rules", [])
        rule_map: dict[str, str] = {}
        for rule in rules:
            rule_id = rule.get("id", "")
            short_desc = rule.get("shortDescription", {}).get("text", "")
            rule_map[rule_id] = short_desc

        # Parse results
        issues: list[CodeIssue] = []
        for result in run.get("results", []):
            issue = SnykCodeParser._parse_result(result, rule_map)
            if issue:
                issues.append(issue)

        return CodeReport(
            ok=len(issues) == 0,
            issues=issues,
            tool_name=tool_name,
            tool_version=tool_version,
        )

    @staticmethod
    def _parse_result(result: dict, rule_map: dict[str, str]) -> CodeIssue | None:
        """Parse a single SARIF result into a CodeIssue."""
        rule_id = result.get("ruleId", "")
        level = result.get("level", "warning")
        severity = SARIF_LEVEL_MAP.get(level, Severity.medium)
        message = result.get("message", {}).get("text", "")
        rule_name = rule_map.get(rule_id, "")

        # Primary location
        locations = result.get("locations", [])
        if not locations:
            return None

        phys = locations[0].get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        region = phys.get("region", {})

        file_path = artifact.get("uri", "")
        start_line = region.get("startLine", 0)
        end_line = region.get("endLine", start_line)
        start_column = region.get("startColumn", 0)
        end_column = region.get("endColumn", 0)

        # Fingerprint
        fingerprints = result.get("fingerprints", {})
        fingerprint = ""
        if fingerprints:
            fingerprint = next(iter(fingerprints.values()), "")

        # Code flow
        code_flow: list[CodeFlowStep] = []
        for cf in result.get("codeFlows", []):
            for tf in cf.get("threadFlows", []):
                for loc_wrapper in tf.get("locations", []):
                    loc = loc_wrapper.get("location", {})
                    loc_phys = loc.get("physicalLocation", {})
                    loc_artifact = loc_phys.get("artifactLocation", {})
                    loc_region = loc_phys.get("region", {})
                    if loc_region:
                        code_flow.append(
                            CodeFlowStep(
                                file_path=loc_artifact.get("uri", ""),
                                start_line=loc_region.get("startLine", 0),
                                end_line=loc_region.get("endLine", 0),
                                start_column=loc_region.get("startColumn", 0),
                                end_column=loc_region.get("endColumn", 0),
                            )
                        )

        # Properties
        props = result.get("properties", {})
        is_autofixable = props.get("isAutofixable", False)
        priority_score = props.get("priorityScore", 0)

        return CodeIssue(
            rule_id=rule_id,
            rule_name=rule_name,
            message=message,
            severity=severity,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            start_column=start_column,
            end_column=end_column,
            fingerprint=fingerprint,
            code_flow=code_flow,
            is_autofixable=is_autofixable,
            priority_score=priority_score,
        )

    @staticmethod
    def filter_by_severity(
        report: CodeReport, min_severity: Severity
    ) -> list[CodeIssue]:
        """Return issues at or above the given severity."""
        return [i for i in report.issues if i.severity >= min_severity]

    @staticmethod
    def deduplicate(issues: list[CodeIssue]) -> list[CodeIssue]:
        """Remove duplicate issues by fingerprint or (rule_id, file, line)."""
        seen: set[str] = set()
        unique: list[CodeIssue] = []
        for issue in issues:
            key = issue.fingerprint or f"{issue.rule_id}:{issue.file_path}:{issue.start_line}"
            if key not in seen:
                seen.add(key)
                unique.append(issue)
        return unique
