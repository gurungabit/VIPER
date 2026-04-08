"""Generate vulnerability reports in various formats."""

from __future__ import annotations

import json
from datetime import datetime

from rich.console import Console
from rich.table import Table

from viper.models.vulnerability import Severity, SnykReport


class ReportGenerator:
    """Generate vulnerability remediation reports."""

    def generate_markdown(self, report: SnykReport) -> str:
        """Generate a markdown vulnerability report."""
        lines = [
            "# VIPER Vulnerability Report",
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Project: {report.project_name or 'Unknown'}",
            f"Package Manager: {report.package_manager or 'Unknown'}",
            f"Total Dependencies: {report.dependency_count}",
            f"Vulnerabilities Found: {len(report.vulnerabilities)}",
            "",
        ]

        if not report.vulnerabilities:
            lines.append("**No vulnerabilities found.**")
            return "\n".join(lines)

        # Summary by severity
        by_sev: dict[str, int] = {}
        for v in report.vulnerabilities:
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1

        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low"]:
            if sev in by_sev:
                lines.append(f"| {sev.upper()} | {by_sev[sev]} |")
        lines.append("")

        # Detailed vulnerability list
        lines.append("## Vulnerabilities")
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

        # Group by package for remediation guidance
        packages: dict[str, list] = {}
        for v in report.vulnerabilities:
            packages.setdefault(v.package_name, []).append(v)

        lines.append("## Remediation Guidance")
        lines.append("")
        for pkg, vulns in sorted(packages.items()):
            unique_vulns = {v.id: v for v in vulns}
            lines.append(f"### {pkg}@{vulns[0].version}")
            lines.append(f"- **{len(unique_vulns)} vulnerabilities**")
            max_sev = max(v.severity for v in unique_vulns.values())
            lines.append(f"- Highest severity: **{max_sev.value.upper()}**")
            if vulns[0].is_upgradable:
                upgrade = [
                    p for p in vulns[0].upgrade_path
                    if isinstance(p, str)
                ]
                if upgrade:
                    lines.append(f"- Upgrade path: {' -> '.join(upgrade)}")
            lines.append("")

        return "\n".join(lines)

    def generate_json(self, report: SnykReport) -> str:
        """Generate a JSON vulnerability report."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "project": report.project_name,
            "package_manager": report.package_manager,
            "dependency_count": report.dependency_count,
            "vulnerability_count": len(report.vulnerabilities),
            "summary": {},
            "vulnerabilities": [],
        }

        by_sev: dict[str, int] = {}
        for v in report.vulnerabilities:
            by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
        data["summary"] = by_sev

        seen: set[str] = set()
        for v in sorted(
            report.vulnerabilities,
            key=lambda x: x.severity.rank,
            reverse=True,
        ):
            if v.id in seen:
                continue
            seen.add(v.id)
            data["vulnerabilities"].append({
                "id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "package": v.package_name,
                "version": v.version,
                "is_upgradable": v.is_upgradable,
                "exploit_maturity": v.exploit_maturity,
                "cvss_score": v.cvss_score,
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
