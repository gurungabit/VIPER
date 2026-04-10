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
from viper.models.code_issue import CodeIssue, CodeReport
from viper.models.result import AgentResult, FileChange
from viper.models.vulnerability import Severity, SnykReport
from viper.parsers.snyk_code_parser import SnykCodeParser
from viper.parsers.snyk_parser import SnykParser


console = Console()


@dataclass
class RemediationBatch:
    """A set of compatible fix units that can be remediated together."""

    key: str
    label: str
    install_root: str
    actions: list[FixAction] = field(default_factory=list)

    @property
    def max_severity_rank(self) -> int:
        return max(Severity(action.severity.lower()).rank for action in self.actions)

    @property
    def max_severity(self) -> str:
        highest = max(self.actions, key=lambda action: Severity(action.severity.lower()).rank)
        return highest.severity


@dataclass
class BatchAttempt:
    """Result for a single remediation batch."""

    batch: RemediationBatch
    success: bool = False
    fixed_count: int = 0
    attempts_used: int = 0
    summary: str = ""
    validation_report: SnykReport | None = None
    changes: list[FileChange] = field(default_factory=list)


@dataclass
class CodeBatch:
    """A set of code issues in the same file to remediate together."""

    key: str  # file path
    issues: list[CodeIssue] = field(default_factory=list)

    @property
    def max_severity_rank(self) -> int:
        return max(i.severity.rank for i in self.issues) if self.issues else 0

    @property
    def max_severity(self) -> str:
        if not self.issues:
            return "LOW"
        highest = max(self.issues, key=lambda i: i.severity.rank)
        return highest.severity.value.upper()


@dataclass
class CodeBatchAttempt:
    """Result for a single code remediation batch."""

    batch: CodeBatch
    success: bool = False
    fixed_count: int = 0
    attempts_used: int = 0
    summary: str = ""
    validation_report: CodeReport | None = None
    changes: list[FileChange] = field(default_factory=list)


@dataclass
class DepFixRecord:
    """Record of a single dependency fix applied."""

    package: str
    old_version: str
    new_version: str
    severity: str
    file_path: str
    mode: str  # "direct" or "override"


@dataclass
class CodeFixRecord:
    """Record of a single code issue fix applied."""

    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    start_line: int
    message: str
    fix_description: str = ""


@dataclass
class AutoRunResult:
    """Top-level result for `viper auto`."""

    cycles_completed: int
    total_fixed: int
    changes: list[FileChange]
    clean: bool
    duration_seconds: float
    code_cycles_completed: int = 0
    code_total_fixed: int = 0
    # Detailed records for report generation
    dep_fixes_planned: list[DepFixRecord] = field(default_factory=list)
    code_fixes_planned: list[CodeFixRecord] = field(default_factory=list)
    dep_remaining: int = 0
    code_remaining: int = 0
    project_dir: str = ""


class RemediationOrchestrator:
    """Drive scan -> select batch -> fix -> verify -> retry."""

    def __init__(
        self,
        config: ViperConfig,
        project_dir: Path,
        severity_threshold: str,
        max_cycles: int,
        use_ai: bool = True,
        stream_agent: bool = True,
        verbose: bool = False,
        scan_code: bool = True,
    ):
        self.config = config
        self.project_dir = project_dir.resolve()
        self.severity_threshold = Severity(severity_threshold)
        self.max_cycles = max_cycles
        self.use_ai = use_ai
        self.stream_agent = stream_agent
        self.verbose = verbose
        self.scan_code = scan_code
        self.max_attempts_per_batch = 3

    def run(self) -> AutoRunResult:
        """Run the remediation loop end-to-end."""
        all_changes: list[FileChange] = []
        total_fixed = 0
        start_time = time.time()
        cycles_completed = 0
        clean = False
        dep_fix_records: list[DepFixRecord] = []
        code_fix_records: list[CodeFixRecord] = []
        dep_remaining = 0
        code_remaining = 0

        for cycle in range(1, self.max_cycles + 1):
            cycles_completed = cycle
            console.rule(
                f"[bold cyan]Cycle {cycle} of {self.max_cycles}[/bold cyan]",
                style="cyan",
            )
            console.print()

            try:
                report = self._scan()
            except ViperError as e:
                console.print(f"[yellow]Dependency scan skipped: {e}[/yellow]")
                clean = True  # no deps to scan = clean for SCA
                break
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
            batches = self._plan_batches(units)
            console.print(
                f"  [bold]Found {len(vulns)} vulnerabilities[/bold] "
                f"(from {report.dependency_count} dependencies)"
            )
            console.print(
                f"  [bold]Actionable fix units:[/bold] {len(units)} "
                f"at {self.severity_threshold.value}+ severity\n"
            )
            self._display_units(units)

            if not batches:
                console.print(
                    "\n[yellow]No safe actionable fix units remain. "
                    "Stopping without broad upgrade guesses.[/yellow]"
                )
                break

            selected_batch = batches[0]
            console.print()
            console.print(
                f"[bold][2/3] Selected batch:[/bold] "
                f"[{selected_batch.max_severity.lower()}]{selected_batch.max_severity}[/{selected_batch.max_severity.lower()}] "
                f"{len(selected_batch.actions)} fix unit(s) "
                f"in install root [bold]{selected_batch.install_root}[/bold]"
            )
            for action in selected_batch.actions:
                console.print(
                    f"  - {action.package} {action.current_version} -> {action.fix_version} "
                    f"in {action.file_path} "
                    f"({'direct' if action.is_direct else 'override'})"
                )
                dep_fix_records.append(DepFixRecord(
                    package=action.package,
                    old_version=action.current_version,
                    new_version=action.fix_version,
                    severity=action.severity,
                    file_path=action.file_path,
                    mode="direct" if action.is_direct else "override",
                ))

            attempt = self._remediate_batch(selected_batch, filtered_report)
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
                    "\n[red]No validated progress on the selected batch — stopping.[/red]"
                )
                break

        else:
            console.print(
                f"\n[yellow]Reached max cycles ({self.max_cycles}). "
                "Some vulnerabilities may remain.[/yellow]"
            )

        dep_remaining = total_fixed  # will be overwritten below if we have data
        # Try to get actual remaining count from last validation
        if not clean:
            try:
                final_sca = self._scan()
                final_filtered = self._filter_report(final_sca)
                dep_remaining = len(self._remaining_vulns(final_filtered))
            except ViperError:
                dep_remaining = 0
        else:
            dep_remaining = 0

        # ── Phase 2: Code (SAST) remediation ──────────────────────
        code_cycles = 0
        code_fixed = 0
        code_clean = True

        if self.scan_code:
            console.print()
            console.rule("[bold magenta]Phase 2: Code Security (SAST)[/bold magenta]", style="magenta")
            console.print()

            for code_cycle in range(1, self.max_cycles + 1):
                code_cycles = code_cycle
                console.rule(
                    f"[bold magenta]Code Cycle {code_cycle} of {self.max_cycles}[/bold magenta]",
                    style="magenta",
                )
                console.print()

                try:
                    code_report = self._code_scan()
                except ViperError as e:
                    console.print(f"[yellow]Code scan skipped: {e}[/yellow]")
                    break

                filtered_issues = SnykCodeParser.filter_by_severity(
                    code_report, self.severity_threshold
                )
                filtered_issues = SnykCodeParser.deduplicate(filtered_issues)

                if not filtered_issues:
                    console.print(
                        Panel(
                            "[bold green]No code security issues found![/bold green]",
                            border_style="green",
                        )
                    )
                    break

                console.print(
                    f"  [bold]Found {len(filtered_issues)} code issues[/bold] "
                    f"at {self.severity_threshold.value}+ severity\n"
                )
                self._display_code_issues(filtered_issues)

                batches = self._plan_code_batches(filtered_issues)
                if not batches:
                    console.print("\n[yellow]No actionable code batches.[/yellow]")
                    code_clean = False
                    break

                selected = batches[0]
                console.print()
                console.print(
                    f"[bold]Selected code batch:[/bold] "
                    f"[{selected.max_severity.lower()}]{selected.max_severity}[/{selected.max_severity.lower()}] "
                    f"{len(selected.issues)} issue(s) in [bold]{selected.key}[/bold]"
                )
                for issue in selected.issues:
                    code_fix_records.append(CodeFixRecord(
                        rule_id=issue.rule_id,
                        rule_name=issue.rule_name or issue.rule_id,
                        severity=issue.severity.value.upper(),
                        file_path=issue.file_path,
                        start_line=issue.start_line,
                        message=issue.message,
                    ))

                attempt = self._remediate_code_batch(
                    selected,
                    code_report,
                )
                all_changes.extend(attempt.changes)
                code_fixed += max(attempt.fixed_count, 0)

                if attempt.success:
                    continue

                if attempt.fixed_count <= 0 and not attempt.changes:
                    console.print(
                        "\n[red]No progress on code batch — stopping.[/red]"
                    )
                    code_clean = False
                    break
            else:
                console.print(
                    f"\n[yellow]Reached max code cycles ({self.max_cycles}).[/yellow]"
                )
                code_clean = False

        return AutoRunResult(
            cycles_completed=cycles_completed,
            total_fixed=total_fixed,
            changes=all_changes,
            clean=clean and code_clean,
            duration_seconds=time.time() - start_time,
            code_cycles_completed=code_cycles,
            code_total_fixed=code_fixed,
            dep_fixes_planned=dep_fix_records,
            code_fixes_planned=code_fix_records,
            dep_remaining=dep_remaining,
            code_remaining=0 if code_clean else len(code_fix_records),
            project_dir=str(self.project_dir),
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

    def _plan_batches(self, units: list[FixAction]) -> list[RemediationBatch]:
        """Group compatible fix units into safe write batches."""
        if not units:
            return []

        fixer = DirectFixer(project_dir=self.project_dir, dry_run=True, verbose=False)
        by_key: dict[str, RemediationBatch] = {}

        for action in units:
            key, label, install_root = self._batch_identity(action, fixer)
            batch = by_key.get(key)
            if batch is None:
                batch = RemediationBatch(
                    key=key,
                    label=label,
                    install_root=install_root,
                )
                by_key[key] = batch
            batch.actions.append(action)

        batches = list(by_key.values())
        for batch in batches:
            batch.actions.sort(
                key=lambda action: (
                    Severity(action.severity.lower()).rank,
                    1 if action.is_direct else 0,
                    action.file_path,
                    action.package,
                ),
                reverse=True,
            )

        return sorted(
            batches,
            key=lambda batch: (
                batch.max_severity_rank,
                len(batch.actions),
                batch.install_root,
                batch.label,
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

    def _remediate_batch(self, batch: RemediationBatch, report: SnykReport) -> BatchAttempt:
        feedback: str | None = None
        attempt_result = BatchAttempt(batch=batch)

        for attempt_number in range(1, self.max_attempts_per_batch + 1):
            attempt_result.attempts_used = attempt_number
            console.print()
            console.print(
                f"[bold]Attempt {attempt_number}/{self.max_attempts_per_batch}[/bold] "
                f"for batch {batch.install_root} ({len(batch.actions)} unit(s))"
            )

            ai_result = self._run_agent_for_batch(batch, report, feedback)
            if ai_result.summary:
                console.print(ai_result.summary)

            if not ai_result.changes:
                console.print(
                    "[yellow]Agent made no file changes for this batch.[/yellow]"
                )

            attempt_result.changes.extend(ai_result.changes)

            # Ensure dependencies are actually installed before validation scan.
            # If node_modules is missing (agent may have deleted it), reinstall first.
            self._ensure_deps_installed(batch)

            validation_report = self._scan()
            attempt_result.validation_report = validation_report

            # Sanity check: if dependency count dropped dramatically, the project
            # is likely broken (e.g. npm install failed). Don't declare victory.
            previous_dep_count = report.dependency_count
            current_dep_count = validation_report.dependency_count
            if (
                previous_dep_count > 0
                and current_dep_count < previous_dep_count * 0.5
            ):
                console.print(
                    f"[red]Dependency count dropped from {previous_dep_count} to "
                    f"{current_dep_count} — project may be broken. Retrying.[/red]"
                )
                feedback = (
                    f"CRITICAL: The dependency count dropped from {previous_dep_count} "
                    f"to {current_dep_count} after your changes. This likely means "
                    "npm install failed or the project is broken. You MUST ensure "
                    "`npm install` succeeds before calling done(). Check for version "
                    "conflicts, invalid version ranges, and fix them."
                )
                continue

            validation_filtered = self._filter_report(validation_report)
            remaining_units = self._plan_units(validation_filtered)
            unresolved_actions = [
                action for action in batch.actions
                if any(self._unit_matches(action, other) for other in remaining_units)
            ]
            current_remaining = len(self._remaining_vulns(validation_report))
            previous_remaining = len(self._remaining_vulns(report))

            if not unresolved_actions:
                attempt_result.success = True
                attempt_result.fixed_count = max(
                    previous_remaining - current_remaining,
                    len(batch.actions),
                )
                attempt_result.summary = (
                    f"Validated batch for {batch.install_root} "
                    f"after {attempt_number} attempt(s)."
                )
                console.print(f"[green]{attempt_result.summary}[/green]")
                return attempt_result

            feedback = self._build_retry_feedback(batch, validation_filtered, attempt_number)
            console.print(
                f"[yellow]Batch still has {len(unresolved_actions)} unresolved unit(s) after attempt {attempt_number}.[/yellow]"
            )
            report = validation_filtered

        attempt_result.summary = (
            f"Unable to validate the batch for {batch.install_root} "
            f"after {self.max_attempts_per_batch} attempts."
        )
        console.print(f"[red]{attempt_result.summary}[/red]")
        return attempt_result

    def _run_agent_for_batch(
        self,
        batch: RemediationBatch,
        report: SnykReport,
        feedback: str | None,
    ) -> AgentResult:
        extra_context = self._collect_batch_context(batch)
        agent = ViperAgent(
            config=self.config,
            project_dir=self.project_dir,
            verbose=self.verbose,
            event_handler=self._handle_agent_event if self.stream_agent else None,
        )
        return asyncio.run(
            agent.run_fix_batch(
                report,
                batch.actions,
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
        batch: RemediationBatch,
        report: SnykReport,
        attempt_number: int,
    ) -> str:
        unit_keys = {(action.package, action.file_path) for action in batch.actions}
        related = []
        for vuln in SnykParser.deduplicate(report.vulnerabilities):
            location = vuln.display_target_file or ""
            if (vuln.package_name, location) in unit_keys or any(
                vuln.package_name == action.package for action in batch.actions
            ):
                related.append(vuln)

        lines = [
            f"The previous attempt did not fully remediate the batch for {batch.install_root}.",
            f"Retry number: {attempt_number + 1}.",
            "Reinspect the owning manifests, shared install root, and dependency tree before editing again.",
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

    def _collect_batch_context(self, batch: RemediationBatch) -> str:
        """Gather a small deterministic context bundle for the selected batch."""
        lines = [
            "The orchestrator already selected the exact target version from Snyk.",
            "Do not query the registry repeatedly. Only do so if install fails unexpectedly.",
        ]

        lines.append(f"Selected install root: {batch.install_root}")
        lines.append(
            "Batch units: "
            + ", ".join(
                f"{action.package}@{action.fix_version} -> {action.file_path}"
                for action in batch.actions
            )
        )

        seen_manifests: set[str] = set()
        for action in batch.actions:
            if action.file_path in seen_manifests:
                continue
            seen_manifests.add(action.file_path)
            manifest_path = self.project_dir / action.file_path
            if not manifest_path.exists():
                continue
            try:
                manifest_text = manifest_path.read_text()
            except OSError:
                continue
            lines.append(f"Manifest path: {action.file_path}")
            lines.append("Manifest excerpt:")
            lines.append(manifest_text[:2200])

        fixer = DirectFixer(project_dir=self.project_dir, dry_run=True, verbose=False)
        install_dir = None
        if batch.actions and batch.actions[0].file_path.endswith("package.json"):
            install_dir = fixer._resolve_install_dir(batch.actions[0].file_path)
            try:
                relative_install_dir = install_dir.relative_to(self.project_dir)
                lines.append(
                    f"Install/lockfile refresh directory: {relative_install_dir or Path('.')}"
                )
            except ValueError:
                lines.append(f"Install/lockfile refresh directory: {install_dir}")

        if install_dir is not None:
            seen_packages: set[str] = set()
            for action in batch.actions:
                if action.package in seen_packages:
                    continue
                seen_packages.add(action.package)
                ls_output = self._run_command(
                    ["npm", "ls", action.package],
                    cwd=install_dir,
                    timeout=25,
                )
                if ls_output:
                    lines.append(f"Prechecked `npm ls {action.package}` output:")
                    lines.append(ls_output)

        return "\n".join(lines)

    def _ensure_deps_installed(self, batch: RemediationBatch) -> None:
        """Ensure node_modules exists before validation scan.

        If the agent deleted node_modules during remediation but npm install
        failed, the validation scan would see 0 dependencies and falsely
        report 0 vulnerabilities. This method detects that and runs install.
        """
        install_dir = self.project_dir / batch.install_root
        node_modules = install_dir / "node_modules"
        package_json = install_dir / "package.json"

        if package_json.exists() and not node_modules.exists():
            console.print(
                "[yellow]node_modules missing after agent run — "
                "running npm install before validation...[/yellow]"
            )
            try:
                result = subprocess.run(
                    ["npm", "install"],
                    cwd=install_dir,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    console.print(
                        f"[red]npm install failed (exit {result.returncode}). "
                        f"Validation scan may be unreliable.[/red]"
                    )
                    stderr_preview = (result.stderr or "")[:300]
                    if stderr_preview:
                        console.print(f"  [dim]{stderr_preview}[/dim]")
            except Exception as e:
                console.print(f"[red]npm install error: {e}[/red]")

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

    def _batch_identity(
        self,
        action: FixAction,
        fixer: DirectFixer,
    ) -> tuple[str, str, str]:
        """Return a stable batch key/label/install-root for a fix action."""
        if action.file_path.endswith("package.json"):
            install_dir = fixer._resolve_install_dir(action.file_path)
            try:
                relative = install_dir.relative_to(self.project_dir)
                install_root = str(relative) if str(relative) != "." else "."
            except ValueError:
                install_root = str(install_dir)
            return (
                f"npm:{install_root}",
                f"npm batch @ {install_root}",
                install_root,
            )

        manifest_path = self.project_dir / action.file_path
        parent = manifest_path.parent
        try:
            relative_parent = parent.relative_to(self.project_dir)
            install_root = str(relative_parent) if str(relative_parent) != "." else "."
        except ValueError:
            install_root = str(parent)
        return (
            f"manifest:{install_root}",
            f"manifest batch @ {install_root}",
            install_root,
        )

    # ── Code (SAST) methods ───────────────────────────────────

    def _code_scan(self) -> CodeReport:
        """Run Snyk Code scan with spinner."""
        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Scanning source code with Snyk Code (SAST)...", total=None)
            return SnykCodeParser.run_code_scan(
                project_dir=self.project_dir,
                snyk_token=self.config.snyk.token or None,
                org=self.config.snyk.org or None,
            )

    def _display_code_issues(self, issues: list[CodeIssue]) -> None:
        """Display code issues in a Rich table."""
        table = Table(title=f"Code Issues ({len(issues)} found)", show_lines=True)
        table.add_column("Sev", width=8)
        table.add_column("Rule", min_width=20)
        table.add_column("File", min_width=20)
        table.add_column("Lines", width=10)
        table.add_column("Message", min_width=30)

        severity_colors = {
            Severity.critical: "red",
            Severity.high: "bright_red",
            Severity.medium: "yellow",
            Severity.low: "blue",
        }

        for issue in sorted(issues, key=lambda i: i.severity.rank, reverse=True)[:15]:
            color = severity_colors.get(issue.severity, "white")
            table.add_row(
                f"[{color}]{issue.severity.value.upper()}[/{color}]",
                issue.rule_name or issue.rule_id,
                issue.file_path,
                f"{issue.start_line}-{issue.end_line}",
                issue.message[:80] + ("..." if len(issue.message) > 80 else ""),
            )

        if len(issues) > 15:
            table.caption = f"Showing top 15 of {len(issues)} issues"

        console.print(table)

    def _plan_code_batches(self, issues: list[CodeIssue]) -> list[CodeBatch]:
        """Group code issues by file path into batches."""
        by_file: dict[str, CodeBatch] = {}
        for issue in issues:
            key = issue.file_path
            if key not in by_file:
                by_file[key] = CodeBatch(key=key)
            by_file[key].issues.append(issue)

        batches = list(by_file.values())
        return sorted(
            batches,
            key=lambda b: (b.max_severity_rank, len(b.issues)),
            reverse=True,
        )

    def _remediate_code_batch(
        self,
        batch: CodeBatch,
        report: CodeReport,
    ) -> CodeBatchAttempt:
        """Attempt to fix a batch of code issues via AI agent."""
        feedback: str | None = None
        attempt_result = CodeBatchAttempt(batch=batch)

        for attempt_number in range(1, self.max_attempts_per_batch + 1):
            attempt_result.attempts_used = attempt_number
            console.print()
            console.print(
                f"[bold]Code Attempt {attempt_number}/{self.max_attempts_per_batch}[/bold] "
                f"for {batch.key} ({len(batch.issues)} issue(s))"
            )

            ai_result = self._run_agent_for_code_batch(batch, report, feedback)
            if ai_result.summary:
                console.print(ai_result.summary)

            if not ai_result.changes:
                console.print("[yellow]Agent made no code changes.[/yellow]")

            attempt_result.changes.extend(ai_result.changes)

            # Re-scan to validate
            try:
                validation_report = self._code_scan()
            except ViperError as e:
                console.print(f"[yellow]Validation code scan failed: {e}[/yellow]")
                break

            attempt_result.validation_report = validation_report

            # Check if batch issues are resolved
            remaining_fingerprints = {i.fingerprint for i in validation_report.issues if i.fingerprint}
            batch_fingerprints = {i.fingerprint for i in batch.issues if i.fingerprint}
            unresolved = batch_fingerprints & remaining_fingerprints

            # Also check by rule_id + file + line for issues without fingerprints
            remaining_keys = {
                (i.rule_id, i.file_path, i.start_line) for i in validation_report.issues
            }
            batch_keys = {
                (i.rule_id, i.file_path, i.start_line) for i in batch.issues
            }
            unresolved_keys = batch_keys & remaining_keys

            previous_count = len(batch.issues)
            current_unresolved = len(unresolved) + len(unresolved_keys - {
                (i.rule_id, i.file_path, i.start_line)
                for i in batch.issues if i.fingerprint in unresolved
            })

            if not unresolved and not unresolved_keys:
                attempt_result.success = True
                attempt_result.fixed_count = previous_count
                attempt_result.summary = (
                    f"Code batch for {batch.key} validated "
                    f"after {attempt_number} attempt(s)."
                )
                console.print(f"[green]{attempt_result.summary}[/green]")
                return attempt_result

            # Build feedback for retry
            feedback = self._build_code_retry_feedback(batch, validation_report, attempt_number)
            console.print(
                f"[yellow]Code batch still has unresolved issues after attempt {attempt_number}.[/yellow]"
            )

        attempt_result.summary = (
            f"Unable to fully validate code batch for {batch.key} "
            f"after {self.max_attempts_per_batch} attempts."
        )
        console.print(f"[red]{attempt_result.summary}[/red]")
        return attempt_result

    def _run_agent_for_code_batch(
        self,
        batch: CodeBatch,
        report: CodeReport,
        feedback: str | None,
    ) -> AgentResult:
        """Run the AI agent to fix a batch of code issues."""
        agent = ViperAgent(
            config=self.config,
            project_dir=self.project_dir,
            verbose=self.verbose,
            event_handler=self._handle_agent_event if self.stream_agent else None,
        )
        return asyncio.run(
            agent.run_fix_code_batch(
                report,
                batch.issues,
                feedback=feedback,
            )
        )

    def _build_code_retry_feedback(
        self,
        batch: CodeBatch,
        report: CodeReport,
        attempt_number: int,
    ) -> str:
        """Build feedback for a failed code remediation attempt."""
        lines = [
            f"The previous attempt did not fully fix code issues in {batch.key}.",
            f"Retry number: {attempt_number + 1}.",
            "Re-read the source file, check if your previous edits were correct, "
            "and try a different approach if needed.",
        ]

        # Show remaining issues for this file
        remaining = [i for i in report.issues if i.file_path == batch.key]
        if remaining:
            lines.append("Remaining issues in this file:")
            for issue in remaining[:6]:
                lines.append(
                    f"- [{issue.severity.value.upper()}] {issue.rule_id} "
                    f"at line {issue.start_line}: {issue.message[:120]}"
                )

        return "\n".join(lines)
