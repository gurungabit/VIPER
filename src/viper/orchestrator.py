"""Orchestrated dependency remediation loop for VIPER."""

from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from viper import ViperError
from viper.agent.loop import ViperAgent
from viper.config import ViperConfig
from viper.fixer import DirectFixer, FixAction
from viper.models.result import AgentResult, FileChange
from viper.models.vulnerability import Severity, SnykReport
from viper.parsers.snyk_parser import SnykParser


console = Console()


@dataclass
class UnitAttempt:
    """Result for a single remediation unit."""

    unit: FixAction
    success: bool = False
    fixed_count: int = 0
    attempts_used: int = 0
    summary: str = ""
    validation_report: SnykReport | None = None
    changes: list[FileChange] = field(default_factory=list)
    used_fallback: bool = False


@dataclass
class AutoRunResult:
    """Top-level result for `viper auto`."""

    cycles_completed: int
    total_fixed: int
    changes: list[FileChange]
    clean: bool
    duration_seconds: float


class RemediationOrchestrator:
    """Drive scan -> select unit -> fix -> verify -> retry."""

    def __init__(
        self,
        config: ViperConfig,
        project_dir: Path,
        severity_threshold: str,
        max_cycles: int,
        use_ai: bool = True,
        stream_agent: bool = True,
        verbose: bool = False,
    ):
        self.config = config
        self.project_dir = project_dir.resolve()
        self.severity_threshold = Severity(severity_threshold)
        self.max_cycles = max_cycles
        self.use_ai = use_ai
        self.stream_agent = stream_agent
        self.verbose = verbose
        self.max_attempts_per_unit = 3

    def run(self) -> AutoRunResult:
        """Run the remediation loop end-to-end."""
        all_changes: list[FileChange] = []
        total_fixed = 0
        start_time = time.time()
        cycles_completed = 0
        clean = False

        for cycle in range(1, self.max_cycles + 1):
            cycles_completed = cycle
            console.rule(
                f"[bold cyan]Cycle {cycle} of {self.max_cycles}[/bold cyan]",
                style="cyan",
            )
            console.print()

            report = self._scan()
            filtered_report = self._filter_report(report)
            vulns = SnykParser.deduplicate(filtered_report.vulnerabilities)

            if not vulns:
                console.print(
                    Panel(
                        "[bold green]Project is clean! No vulnerabilities found.[/bold green]",
                        border_style="green",
                    )
                )
                clean = True
                break

            units = self._plan_units(filtered_report)
            console.print(
                f"  [bold]Found {len(vulns)} vulnerabilities[/bold] "
                f"(from {report.dependency_count} dependencies)"
            )
            console.print(
                f"  [bold]Actionable fix units:[/bold] {len(units)} "
                f"at {self.severity_threshold.value}+ severity\n"
            )
            self._display_units(units)

            if not units:
                console.print(
                    "\n[yellow]No safe actionable fix units remain. "
                    "Stopping without broad upgrade guesses.[/yellow]"
                )
                break

            selected_unit = units[0]
            console.print()
            console.print(
                f"[bold][2/3] Selected fix unit:[/bold] "
                f"[{selected_unit.severity.lower()}]{selected_unit.severity}[/{selected_unit.severity.lower()}] "
                f"{selected_unit.package} {selected_unit.current_version} -> {selected_unit.fix_version} "
                f"in {selected_unit.file_path} "
                f"({'direct' if selected_unit.is_direct else 'override'})"
            )

            attempt = self._remediate_unit(selected_unit, filtered_report)
            all_changes.extend(attempt.changes)
            total_fixed += max(attempt.fixed_count, 0)

            validation_report = attempt.validation_report or filtered_report
            remaining = self._remaining_vulns(validation_report)

            if not remaining:
                console.print(
                    Panel(
                        "[bold green]All actionable vulnerabilities resolved![/bold green]",
                        border_style="green",
                    )
                )
                clean = True
                break

            console.print()
            console.print(
                f"  [yellow]{len(remaining)} vulnerabilities remaining[/yellow] "
                f"([green]{attempt.fixed_count} fixed[/green] this cycle)"
            )

            if attempt.fixed_count <= 0 and not attempt.changes:
                console.print(
                    "\n[red]No validated progress on the selected fix unit — stopping.[/red]"
                )
                break

        else:
            console.print(
                f"\n[yellow]Reached max cycles ({self.max_cycles}). "
                "Some vulnerabilities may remain.[/yellow]"
            )

        return AutoRunResult(
            cycles_completed=cycles_completed,
            total_fixed=total_fixed,
            changes=all_changes,
            clean=clean,
            duration_seconds=time.time() - start_time,
        )

    def _scan(self) -> SnykReport:
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("[1/3] Scanning all projects with Snyk...", total=None)
            return SnykParser.run_scan(
                project_dir=self.project_dir,
                snyk_token=self.config.snyk.token or None,
                org=self.config.snyk.org or None,
            )

    def _filter_report(self, report: SnykReport) -> SnykReport:
        filtered = SnykParser.filter_by_severity(report, self.severity_threshold)
        return report.model_copy(
            update={
                "vulnerabilities": filtered,
                "unique_count": len(SnykParser.deduplicate(filtered)),
                "ok": len(filtered) == 0,
            }
        )

    def _remaining_vulns(self, report: SnykReport) -> list:
        return SnykParser.deduplicate(
            SnykParser.filter_by_severity(report, self.severity_threshold)
        )

    def _plan_units(self, report: SnykReport) -> list[FixAction]:
        fixer = DirectFixer(project_dir=self.project_dir, dry_run=True, verbose=False)
        actions = fixer.plan_fixes(report)
        return sorted(
            actions,
            key=lambda action: (
                Severity(action.severity.lower()).rank,
                1 if action.is_direct else 0,
                action.file_path,
                action.package,
            ),
            reverse=True,
        )

    def _display_units(self, units: list[FixAction]) -> None:
        table = Table(title=f"Strategic Fix Units ({len(units)} planned)", show_lines=True)
        table.add_column("Sev", width=8)
        table.add_column("Package", min_width=18)
        table.add_column("Current", width=10)
        table.add_column("Target", width=10)
        table.add_column("Mode", width=10)
        table.add_column("File", min_width=20)

        for unit in units[:12]:
            color = {
                "CRITICAL": "red",
                "HIGH": "bright_red",
                "MEDIUM": "yellow",
                "LOW": "blue",
            }.get(unit.severity, "white")
            table.add_row(
                f"[{color}]{unit.severity}[/{color}]",
                unit.package,
                unit.current_version,
                unit.fix_version,
                "direct" if unit.is_direct else "override",
                unit.file_path,
            )

        if len(units) > 12:
            table.caption = f"Showing top 12 of {len(units)} actionable fix units"

        console.print(table)

    def _remediate_unit(self, unit: FixAction, report: SnykReport) -> UnitAttempt:
        feedback: str | None = None
        attempt_result = UnitAttempt(unit=unit)

        for attempt_number in range(1, self.max_attempts_per_unit + 1):
            attempt_result.attempts_used = attempt_number
            console.print()
            console.print(
                f"[bold]Attempt {attempt_number}/{self.max_attempts_per_unit}[/bold] "
                f"for {unit.package} in {unit.file_path}"
            )

            ai_result: AgentResult | None = None
            if self.use_ai:
                ai_result = self._run_agent_for_unit(unit, report, feedback)
                if ai_result.summary:
                    console.print(ai_result.summary)

            used_fallback = False
            if (ai_result is None or not ai_result.changes) and self.use_ai:
                console.print(
                    "[yellow]Agent made no file changes for this unit. "
                    "Trying deterministic single-unit remediation.[/yellow]"
                )
                used_fallback = True

            if used_fallback or not self.use_ai:
                fallback_result = DirectFixer(
                    project_dir=self.project_dir,
                    dry_run=self.config.dry_run,
                    verbose=True,
                ).fix_action(unit)
                ai_result = fallback_result
                if fallback_result.summary:
                    console.print(fallback_result.summary)

            attempt_result.used_fallback = attempt_result.used_fallback or used_fallback
            if ai_result:
                attempt_result.changes.extend(ai_result.changes)

            validation_report = self._scan()
            attempt_result.validation_report = validation_report
            validation_filtered = self._filter_report(validation_report)
            remaining_units = self._plan_units(validation_filtered)
            still_present = any(self._unit_matches(unit, other) for other in remaining_units)
            current_remaining = len(self._remaining_vulns(validation_report))
            previous_remaining = len(self._remaining_vulns(report))

            if not still_present:
                attempt_result.success = True
                attempt_result.fixed_count = max(previous_remaining - current_remaining, 1)
                attempt_result.summary = (
                    f"Validated fix for {unit.package} in {unit.file_path} "
                    f"after {attempt_number} attempt(s)."
                )
                console.print(f"[green]{attempt_result.summary}[/green]")
                return attempt_result

            feedback = self._build_retry_feedback(unit, validation_filtered, attempt_number)
            console.print(
                f"[yellow]Unit still unresolved after attempt {attempt_number}.[/yellow]"
            )
            report = validation_filtered

        attempt_result.summary = (
            f"Unable to validate a fix for {unit.package} in {unit.file_path} "
            f"after {self.max_attempts_per_unit} attempts."
        )
        console.print(f"[red]{attempt_result.summary}[/red]")
        return attempt_result

    def _run_agent_for_unit(
        self,
        unit: FixAction,
        report: SnykReport,
        feedback: str | None,
    ) -> AgentResult:
        extra_context = self._collect_unit_context(unit)
        agent = ViperAgent(
            config=self.config,
            project_dir=self.project_dir,
            verbose=self.verbose,
            event_handler=self._handle_agent_event if self.stream_agent else None,
        )
        return asyncio.run(
            agent.run_fix_unit(
                report,
                unit,
                feedback=feedback,
                extra_context=extra_context,
            )
        )

    def _handle_agent_event(self, event_type: str, payload: dict[str, Any]) -> None:
        if event_type == "iteration_start":
            console.print(
                f"  [cyan]Agent iteration {payload['iteration']}/{self.config.agent.max_iterations}[/cyan]"
            )
            return

        if event_type == "assistant_message":
            content = str(payload.get("content", "")).strip()
            if content:
                console.print(f"  [blue]Agent:[/blue] {content}")
            return

        if event_type == "tool_call":
            console.print(
                f"  [yellow]Tool:[/yellow] {payload['tool_name']}({payload['args_preview']})"
            )
            return

        if event_type == "tool_result":
            console.print(f"    [dim]{payload['result_preview']}[/dim]")
            return

        if event_type == "nudge":
            console.print(f"  [magenta]{payload['message']}[/magenta]")
            return

        if event_type == "completed":
            console.print("  [green]Agent completed[/green]")
            return

        if event_type == "max_iterations":
            console.print(
                f"  [yellow]Agent hit the iteration cap ({payload['limit']}).[/yellow]"
            )

    def _build_retry_feedback(
        self,
        unit: FixAction,
        report: SnykReport,
        attempt_number: int,
    ) -> str:
        related = [
            vuln for vuln in SnykParser.deduplicate(report.vulnerabilities)
            if vuln.package_name == unit.package
        ]
        lines = [
            f"The previous attempt did not fully remediate {unit.package} in {unit.file_path}.",
            f"Retry number: {attempt_number + 1}.",
            "Reinspect the owning manifest, workspace root, and dependency tree before editing again.",
        ]

        if related:
            lines.append("Remaining related Snyk findings:")
            for vuln in related[:8]:
                location = vuln.display_target_file or vuln.source_project_name or "unknown target"
                lines.append(
                    f"- {vuln.id}: {vuln.package_name}@{vuln.version} "
                    f"| target={location} | severity={vuln.severity.value.upper()}"
                )

        return "\n".join(lines)

    def _collect_unit_context(self, unit: FixAction) -> str:
        """Gather a small deterministic context bundle for the selected unit."""
        lines = [
            "The orchestrator already selected the exact target version from Snyk.",
            "Do not query the registry repeatedly. Only do so if install fails unexpectedly.",
        ]

        manifest_path = self.project_dir / unit.file_path
        if manifest_path.exists():
            try:
                manifest_text = manifest_path.read_text()
                lines.append(f"Manifest path: {unit.file_path}")
                lines.append("Manifest excerpt:")
                snippet = manifest_text[:3000]
                lines.append(snippet)
            except OSError:
                pass

        if unit.file_path.endswith("package.json"):
            fixer = DirectFixer(project_dir=self.project_dir, dry_run=True, verbose=False)
            install_dir = fixer._resolve_install_dir(unit.file_path)
            relative_install_dir = install_dir.relative_to(self.project_dir)
            lines.append(f"Install/lockfile refresh directory: {relative_install_dir or Path('.')}")

            ls_output = self._run_command(
                ["npm", "ls", unit.package],
                cwd=install_dir,
                timeout=25,
            )
            if ls_output:
                lines.append("Prechecked `npm ls` output:")
                lines.append(ls_output)

            registry_output = self._run_command(
                ["npm", "view", f"{unit.package}@{unit.fix_version}", "version"],
                cwd=install_dir,
                timeout=25,
            )
            if registry_output:
                lines.append("Prechecked target registry query:")
                lines.append(registry_output)

        return "\n".join(lines)

    def _run_command(self, args: list[str], cwd: Path, timeout: int) -> str:
        """Run a small precheck command and return a short preview."""
        try:
            result = subprocess.run(
                args,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except Exception:
            return ""

        output = (result.stdout or result.stderr or "").strip()
        if not output:
            return ""
        compact = " ".join(output.split())
        return compact[:500] + ("..." if len(compact) > 500 else "")

    @staticmethod
    def _unit_matches(selected: FixAction, other: FixAction) -> bool:
        return (
            selected.package == other.package
            and selected.file_path == other.file_path
            and selected.is_direct == other.is_direct
        )
