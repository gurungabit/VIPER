"""Generate vulnerability reports in various formats."""

from __future__ import annotations

import json
from datetime import datetime

from rich.console import Console
from rich.table import Table

from viper.models.code_issue import CodeIssue, CodeReport
from viper.models.vulnerability import Severity, SnykReport


class ReportGenerator:
    """Generate vulnerability remediation reports."""

    def generate_markdown(
        self,
        report: SnykReport,
        code_report: CodeReport | None = None,
    ) -> str:
        """Generate a markdown vulnerability report covering SCA and optionally SAST."""
        lines = [
            "# VIPER Vulnerability Report",
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Project: {report.project_name or 'Unknown'}",
            f"Package Manager: {report.package_manager or 'Unknown'}",
            f"Total Dependencies: {report.dependency_count}",
            "",
        ]

        total_issues = len(report.vulnerabilities)
        if code_report:
            total_issues += len(code_report.issues)
        lines.append(f"Total Issues Found: {total_issues}")
        lines.append("")

        # ── SCA Section ───────────────────────────────────────
        lines.append("## Dependency Vulnerabilities (SCA)")
        lines.append("")

        if not report.vulnerabilities:
            lines.append("**No dependency vulnerabilities found.**")
            lines.append("")
        else:
            self._append_sca_section(lines, report)

        # ── SAST Section ──────────────────────────────────────
        if code_report is not None:
            lines.append("## Source Code Security Issues (SAST)")
            lines.append("")
            if not code_report.issues:
                lines.append("**No code security issues found.**")
                lines.append("")
            else:
                self._append_sast_section(lines, code_report)

        return "\n".join(lines)

    def _append_sca_section(self, lines: list[str], report: SnykReport) -> None:
        """Append SCA vulnerability details to the report lines."""
        by_sev: dict[str, int] = {}
        for v in report.vulnerabilities:
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1

        lines.append(f"**{len(report.vulnerabilities)} vulnerabilities found**")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_sev:
                lines.append(f"| {sev.upper()} | {by_sev[sev]} |")
        lines.append("")

        lines.append("### Vulnerability Details")
        lines.append("")
        lines.append("| Severity | Package | Version | Title | Upgradable | ID |")
        lines.append("|----------|---------|---------|-------|------------|-----|")

        seen_ids: set[str] = set()
        for v in sorted(
            report.vulnerabilities,
            key=lambda x: x.severity.rank,
            reverse=True,
        ):
            if v.id in seen_ids:
                continue
            seen_ids.add(v.id)
            upgradable = "Yes" if v.is_upgradable else "No"
            lines.append(
                f"| {v.severity.value.upper()} | {v.package_name} | "
                f"{v.version} | {v.title} | {upgradable} | {v.id} |"
            )

        lines.append("")

        # Remediation guidance grouped by package
        packages: dict[str, list] = {}
        for v in report.vulnerabilities:
            packages.setdefault(v.package_name, []).append(v)

        lines.append("### Remediation Guidance")
        lines.append("")
        for pkg, vulns in sorted(packages.items()):
            unique_vulns = {v.id: v for v in vulns}
            lines.append(f"**{pkg}@{vulns[0].version}**")
            lines.append(f"- {len(unique_vulns)} vulnerabilities")
            max_sev = max(v.severity for v in unique_vulns.values())
            lines.append(f"- Highest severity: {max_sev.value.upper()}")
            if vulns[0].is_upgradable:
                upgrade = [
                    p for p in vulns[0].upgrade_path
                    if isinstance(p, str)
                ]
                if upgrade:
                    lines.append(f"- Upgrade path: {' -> '.join(upgrade)}")
            lines.append("")

    def _append_sast_section(self, lines: list[str], code_report: CodeReport) -> None:
        """Append SAST code issue details to the report lines."""
        by_sev: dict[str, int] = {}
        for i in code_report.issues:
            by_sev[i.severity.value] = by_sev.get(i.severity.value, 0) + 1

        lines.append(f"**{len(code_report.issues)} issues found**")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["high", "medium", "low"]:
            if sev in by_sev:
                lines.append(f"| {sev.upper()} | {by_sev[sev]} |")
        lines.append("")

        lines.append("### Issue Details")
        lines.append("")
        lines.append("| Severity | Rule | File | Line | Description |")
        lines.append("|----------|------|------|------|-------------|")

        from viper.parsers.snyk_code_parser import SnykCodeParser

        for issue in sorted(
            SnykCodeParser.deduplicate(code_report.issues),
            key=lambda x: x.severity.rank,
            reverse=True,
        ):
            msg = issue.message[:80] + ("..." if len(issue.message) > 80 else "")
            lines.append(
                f"| {issue.severity.value.upper()} | {issue.rule_name or issue.rule_id} | "
                f"`{issue.file_path}` | {issue.start_line} | {msg} |"
            )

        lines.append("")

        # Group by file for guidance
        by_file: dict[str, list[CodeIssue]] = {}
        for issue in code_report.issues:
            by_file.setdefault(issue.file_path, []).append(issue)

        lines.append("### Remediation Guidance")
        lines.append("")
        for file_path, issues in sorted(by_file.items()):
            lines.append(f"**`{file_path}`**")
            for issue in sorted(issues, key=lambda x: x.start_line):
                lines.append(
                    f"- Line {issue.start_line}: [{issue.severity.value.upper()}] "
                    f"{issue.rule_name or issue.rule_id} — {issue.message}"
                )
                if issue.code_flow:
                    lines.append(f"  - Data flow: {len(issue.code_flow)} steps from source to sink")
                if issue.is_autofixable:
                    lines.append("  - Autofixable: Yes")
            lines.append("")

    def generate_json(
        self,
        report: SnykReport,
        code_report: CodeReport | None = None,
    ) -> str:
        """Generate a JSON vulnerability report covering SCA and optionally SAST."""
        data: dict = {
            "generated_at": datetime.now().isoformat(),
            "project": report.project_name,
            "package_manager": report.package_manager,
            "dependency_count": report.dependency_count,
            "sca": {
                "vulnerability_count": len(report.vulnerabilities),
                "summary": {},
                "vulnerabilities": [],
            },
        }

        by_sev: dict[str, int] = {}
        for v in report.vulnerabilities:
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
        data["sca"]["summary"] = by_sev

        seen: set[str] = set()
        for v in sorted(
            report.vulnerabilities,
            key=lambda x: x.severity.rank,
            reverse=True,
        ):
            if v.id in seen:
                continue
            seen.add(v.id)
            data["sca"]["vulnerabilities"].append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "package": v.package_name,
                "version": v.version,
                "is_upgradable": v.is_upgradable,
                "exploit_maturity": v.exploit_maturity,
                "cvss_score": v.cvss_score,
            })

        if code_report is not None:
            data["sast"] = {
                "issue_count": len(code_report.issues),
                "summary": {},
                "issues": [],
            }
            code_by_sev: dict[str, int] = {}
            for i in code_report.issues:
                code_by_sev[i.severity.value] = code_by_sev.get(i.severity.value, 0) + 1
            data["sast"]["summary"] = code_by_sev

            for issue in code_report.issues:
                data["sast"]["issues"].append({
                    "rule_id": issue.rule_id,
                    "rule_name": issue.rule_name,
                    "severity": issue.severity.value,
                    "file_path": issue.file_path,
                    "start_line": issue.start_line,
                    "end_line": issue.end_line,
                    "message": issue.message,
                    "is_autofixable": issue.is_autofixable,
                    "priority_score": issue.priority_score,
                })

        return json.dumps(data, indent=2)

    def generate_table(self, report: SnykReport) -> Table:
        """Generate a Rich table for CLI display."""
        table = Table(title=f"Vulnerability Report ({len(report.vulnerabilities)} found)")
        table.add_column("Severity", style="bold")
        table.add_column("Package")
        table.add_column("Version")
        table.add_column("Title")
        table.add_column("Upgradable")

        severity_colors = {
            Severity.critical: "red",
            Severity.high: "bright_red",
            Severity.medium: "yellow",
            Severity.low: "blue",
        }

        seen: set[str] = set()
        for v in sorted(
            report.vulnerabilities,
            key=lambda x: x.severity.rank,
            reverse=True,
        ):
            if v.id in seen:
                continue
            seen.add(v.id)
            color = severity_colors.get(v.severity, "white")
            table.add_row(
                f"[{color}]{v.severity.value.upper()}[/{color}]",
                v.package_name,
                v.version,
                v.title,
                "Yes" if v.is_upgradable else "No",
            )

        return table
