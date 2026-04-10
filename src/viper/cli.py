"""VIPER CLI — Vulnerability Identification, Patching & Evaluation Robot."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from viper import ViperError, __version__
from viper.config import ViperConfig
from viper.models.vulnerability import Severity, SnykReport
from viper.parsers.snyk_parser import SnykParser

app = typer.Typer(
    name="viper",
    help="VIPER — Vulnerability Identification, Patching & Evaluation Robot",
    no_args_is_help=True,
)
console = Console()

VIPER_BANNER = """[bold cyan]
██╗   ██╗██╗██████╗ ███████╗██████╗
██║   ██║██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██║██████╔╝█████╗  ██████╔╝
╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██║     ███████╗██║  ██║
  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝[/bold cyan] [dim]v{}[/dim]
[dim]Vulnerability Identification, Patching & Evaluation Robot[/dim]
"""


def _load_config(config_path: Path | None) -> ViperConfig:
    if config_path:
        return ViperConfig.load(config_path)
    for p in [Path("viper.yaml"), Path("viper.yml")]:
        if p.exists():
            return ViperConfig.load(p)
    return ViperConfig()


def _run_scan_with_progress(
    project_dir: Path, config: ViperConfig
) -> SnykReport:
    """Run Snyk scan with a spinner."""
    with Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning all projects with Snyk (--dev --all-projects)...", total=None)
        return SnykParser.run_scan(
            project_dir=project_dir,
            snyk_token=config.snyk.token or None,
            org=config.snyk.org or None,
        )


def _filter_report_by_severity(report: SnykReport, min_severity: Severity) -> SnykReport:
    """Return a report copy containing only vulnerabilities at or above the threshold."""
    filtered = SnykParser.filter_by_severity(report, min_severity)
    return report.model_copy(
        update={
            "vulnerabilities": filtered,
            "unique_count": len(SnykParser.deduplicate(filtered)),
            "ok": len(filtered) == 0,
        }
    )


def _resolve_remediation_severity(
    requested: str | None,
    config: ViperConfig,
) -> str:
    """Resolve the effective severity for remediation commands.

    Unless the user explicitly passes --severity, remediation defaults to high+
    even if an older config file still says medium.
    """
    if requested:
        return requested

    configured = config.severity_threshold or "high"
    return configured if Severity(configured) >= Severity.high else Severity.high.value


def _display_vulns(report: SnykReport, severity_filter: str | None = None) -> int:
    """Display vulnerabilities in a Rich table. Returns count displayed."""
    vulns = report.vulnerabilities
    if severity_filter:
        min_sev = Severity(severity_filter)
        vulns = [v for v in vulns if v.severity >= min_sev]

    vulns = SnykParser.deduplicate(vulns)

    if not vulns:
        console.print("[green]No vulnerabilities found![/green]")
        return 0

    table = Table(title=f"Vulnerabilities ({len(vulns)} found)", show_lines=True)
    table.add_column("Sev", style="bold", width=8)
    table.add_column("Package", min_width=18)
    table.add_column("Current", width=10)
    table.add_column("Fix Version", width=12)
    table.add_column("Title", min_width=25)
    table.add_column("ID", style="dim", max_width=30)

    severity_colors = {
        Severity.critical: "red",
        Severity.high: "bright_red",
        Severity.medium: "yellow",
        Severity.low: "blue",
    }

    for v in sorted(vulns, key=lambda x: x.severity.rank, reverse=True):
        color = severity_colors.get(v.severity, "white")
        # Extract fix version — only if it matches this package name
        fix_ver = ""
        if v.is_upgradable:
            for p in v.upgrade_path:
                if isinstance(p, str) and "@" in p:
                    parts = p.rsplit("@", 1)
                    if len(parts) == 2 and parts[0] == v.package_name:
                        fix_ver = parts[1]
                        break
        fix_display = f"[green]{fix_ver}[/green]" if fix_ver else "[red]N/A[/red]"

        table.add_row(
            f"[{color}]{v.severity.value.upper()}[/{color}]",
            v.package_name,
            v.version,
            fix_display,
            v.title,
            v.id,
        )

    console.print(table)

    # Summary bar
    by_sev: dict[str, int] = {}
    for v in vulns:
        by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
    parts = []
    for sev in ["critical", "high", "medium", "low"]:
        if sev in by_sev:
            color = severity_colors[Severity(sev)]
            parts.append(f"[{color}]{by_sev[sev]} {sev}[/{color}]")
    console.print(f"\n  {' | '.join(parts)}")

    return len(vulns)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
) -> None:
    if version:
        console.print(f"VIPER v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        raise typer.Exit()


@app.command()
def init(
    output: Path = typer.Option(
        Path("viper.yaml"), "--output", "-o", help="Output path for config file"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
) -> None:
    """Create a viper.yaml configuration file."""
    import os

    if output.exists() and not force:
        console.print(f"[yellow]{output} already exists.[/yellow] Use --force to overwrite.")
        raise typer.Exit(1)

    config_content = """\
# VIPER Configuration
# Generated by `viper init`

snyk:
  token: "${SNYK_TOKEN}"  # reads from SNYK_TOKEN env var
  org: ""                  # your Snyk organization (optional)

gitlab:
  url: https://gitlab.com
  token: "${VIPER_GITLAB_TOKEN}"  # reads from VIPER_GITLAB_TOKEN env var
  project_id: ""                   # your GitLab project ID
  target_branch: main

ai:
  model: github_copilot/claude-haiku-4.5   # any LiteLLM-supported model
  temperature: 0.2
  max_tokens: 4096

agent:
  max_iterations: 40
  max_no_edit_iterations: 40
  timeout_per_tool: 300
  blocked_commands:
    - "rm -rf /"
    - "sudo"
    - "chmod"
    - "mkfs"
    - "npm audit fix"
    - "npm update"
    - "yarn upgrade"
    - "pnpm up"

settings:
  severity_threshold: high   # low, medium, high, critical
  dry_run: false
"""
    output.write_text(config_content)
    console.print(f"[green]Created {output}[/green]")

    snyk_token = os.environ.get("SNYK_TOKEN", "")
    gitlab_token = os.environ.get("VIPER_GITLAB_TOKEN", "")

    if snyk_token:
        display = f"{snyk_token[:8]}..."
        console.print(f"  SNYK_TOKEN: [green]detected[/green] ({display})")
    else:
        console.print(
            "  SNYK_TOKEN: [red]not set[/red] — "
            "run [bold]export SNYK_TOKEN=<your-token>[/bold] or [bold]snyk auth[/bold]"
        )

    if gitlab_token:
        console.print(f"  VIPER_GITLAB_TOKEN: [green]detected[/green]")
    else:
        console.print("  VIPER_GITLAB_TOKEN: [dim]not set (needed for `viper mr` only)[/dim]")


@app.command()
def scan(
    project_dir: Optional[Path] = typer.Option(None, "--project-dir", "-p", help="Project directory to scan"),
    report_file: Optional[Path] = typer.Option(None, "--report-file", "-r", help="Existing Snyk JSON report"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Minimum severity: low, medium, high, critical"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to viper.yaml"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table, json"),
) -> None:
    """Run Snyk scan and display vulnerabilities."""
    try:
        cfg = _load_config(config)

        if report_file:
            report = SnykParser.parse_file(report_file)
        else:
            target = project_dir or Path.cwd()
            report = _run_scan_with_progress(target, cfg)

        if output == "json":
            console.print_json(report.model_dump_json(indent=2))
        else:
            _display_vulns(report, severity)

    except ViperError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def fix(
    project_dir: Optional[Path] = typer.Option(None, "--project-dir", "-p", help="Project directory"),
    report_file: Optional[Path] = typer.Option(None, "--report-file", "-r", help="Existing Snyk JSON report"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Minimum severity"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to viper.yaml"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes without applying"),
    verbose: bool = typer.Option(False, "--verbose", help="Show details"),
) -> None:
    """Apply Snyk-recommended version fixes directly."""
    try:
        cfg = _load_config(config)
        target_dir = project_dir or Path.cwd()
        sev_threshold = _resolve_remediation_severity(severity, cfg)

        if report_file:
            report = SnykParser.parse_file(report_file)
        else:
            report = _run_scan_with_progress(target_dir, cfg)

        filtered_report = _filter_report_by_severity(report, Severity(sev_threshold))

        if not filtered_report.vulnerabilities:
            console.print(f"[green]No vulnerabilities found at {sev_threshold}+ severity![/green]")
            raise typer.Exit()

        _display_vulns(filtered_report)

        from viper.fixer import DirectFixer

        console.print()
        fixer = DirectFixer(project_dir=target_dir, dry_run=dry_run, verbose=True)
        result = fixer.fix(filtered_report)

        if result.success:
            console.print(f"\n[green]Fix complete![/green]")
            console.print(result.summary)
        else:
            console.print(f"\n[yellow]No fixes applied:[/yellow] {result.summary}")

    except ViperError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def report(
    project_dir: Optional[Path] = typer.Option(None, "--project-dir", "-p", help="Project directory"),
    report_file: Optional[Path] = typer.Option(None, "--report-file", "-r", help="Existing Snyk JSON report"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Minimum severity"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to viper.yaml"),
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, json"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file"),
) -> None:
    """Generate a vulnerability remediation report."""
    try:
        cfg = _load_config(config)
        sev_threshold = severity or cfg.severity_threshold

        if report_file:
            snyk_report = SnykParser.parse_file(report_file)
        else:
            target = project_dir or Path.cwd()
            snyk_report = _run_scan_with_progress(target, cfg)

        snyk_report = _filter_report_by_severity(snyk_report, Severity(sev_threshold))

        from viper.report_generator import ReportGenerator

        generator = ReportGenerator()
        if format == "json":
            content = generator.generate_json(snyk_report)
        else:
            content = generator.generate_markdown(snyk_report)

        if output_file:
            output_file.write_text(content)
            console.print(f"Report written to {output_file}")
        else:
            console.print(content)

    except ViperError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@app.command()
def mr(
    project_dir: Optional[Path] = typer.Option(None, "--project-dir", "-p", help="Project directory"),
    report_file: Optional[Path] = typer.Option(None, "--report-file", "-r", help="Existing Snyk JSON report"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Minimum severity"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to viper.yaml"),
    target_branch: Optional[str] = typer.Option(None, "--target-branch", help="MR target branch"),
    agent_max_iterations: Optional[int] = typer.Option(
        None,
        "--agent-max-iterations",
        help="Override the AI agent tool-use iteration limit for this run",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes without creating MR"),
    verbose: bool = typer.Option(False, "--verbose", help="Show agent tool calls"),
) -> None:
    """Fix vulnerabilities and create a GitLab merge request."""
    try:
        cfg = _load_config(config)
        sev_threshold = _resolve_remediation_severity(severity, cfg)
        if dry_run:
            cfg.dry_run = True
        if target_branch:
            cfg.gitlab.target_branch = target_branch
        if agent_max_iterations is not None:
            cfg.agent.max_iterations = agent_max_iterations

        target_dir = project_dir or Path.cwd()

        if report_file:
            report = SnykParser.parse_file(report_file)
        else:
            report = _run_scan_with_progress(target_dir, cfg)

        filtered_report = _filter_report_by_severity(report, Severity(sev_threshold))

        if not filtered_report.vulnerabilities:
            console.print(f"[green]No vulnerabilities found at {sev_threshold}+ severity![/green]")
            raise typer.Exit()

        from viper.agent.loop import ViperAgent

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            progress.add_task("AI agent fixing vulnerabilities...", total=None)
            agent = ViperAgent(config=cfg, project_dir=target_dir, verbose=verbose)
            result = asyncio.run(agent.run_fix(filtered_report))

        if not result.success:
            console.print(f"[red]Fix failed:[/red] {result.summary}")
            raise typer.Exit(1)

        if cfg.dry_run:
            console.print("[yellow]Dry run — skipping MR creation[/yellow]")
            console.print(result.summary)
            raise typer.Exit()

        from viper.gitlab_integration import GitLabClient

        with Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            progress.add_task("Creating GitLab merge request...", total=None)
            gl = GitLabClient(cfg.gitlab)
            mr_url = asyncio.run(gl.create_fix_mr(result, filtered_report))

        console.print(f"\n[green]Merge request created:[/green] {mr_url}")

    except ViperError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


def _generate_auto_report(result, report_path: Path) -> None:
    """Generate a markdown remediation report from AutoRunResult."""
    from viper.orchestrator import AutoRunResult

    r: AutoRunResult = result
    elapsed = r.duration_seconds
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    lines = [
        "# VIPER Remediation Report",
        "",
        f"**Project:** `{r.project_dir}`",
        f"**Date:** {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Duration:** {minutes}m {seconds}s",
        f"**Status:** {'✅ All clear' if r.clean else '⚠️ Some issues remain'}",
        "",
    ]

    # --- Dependency Remediation ---
    lines.append("## Phase 1: Dependency Vulnerabilities (SCA)")
    lines.append("")
    if r.dep_fixes_planned:
        lines.append(f"**Cycles completed:** {r.cycles_completed}")
        lines.append(f"**Vulnerabilities addressed:** {len(r.dep_fixes_planned)}")
        lines.append(f"**Remaining:** {r.dep_remaining}")
        lines.append("")
        lines.append("### Changes Made")
        lines.append("")
        lines.append("| Severity | Package | Old Version | New Version | File | Mode |")
        lines.append("|----------|---------|-------------|-------------|------|------|")
        seen = set()
        for fix in r.dep_fixes_planned:
            key = (fix.package, fix.new_version)
            if key in seen:
                continue
            seen.add(key)
            lines.append(
                f"| {fix.severity} | {fix.package} | {fix.old_version} | "
                f"{fix.new_version} | {fix.file_path} | {fix.mode} |"
            )
        lines.append("")
        lines.append("### Why These Changes?")
        lines.append("")
        for fix in r.dep_fixes_planned:
            key = (fix.package, fix.new_version)
            if key not in seen:
                continue
            seen.discard(key)  # only print once
            lines.append(
                f"- **{fix.package}** `{fix.old_version}` → `{fix.new_version}`: "
                f"Snyk identified {fix.severity} severity vulnerabilities in this "
                f"{'direct dependency' if fix.mode == 'direct' else 'transitive dependency'}. "
                f"{'Version bumped in' if fix.mode == 'direct' else 'Override added to'} "
                f"`{fix.file_path}`."
            )
        lines.append("")
    else:
        lines.append("No dependency vulnerabilities found or addressed.")
        lines.append("")

    # --- Code Remediation ---
    lines.append("## Phase 2: Code Security (SAST)")
    lines.append("")
    if r.code_fixes_planned:
        lines.append(f"**Cycles completed:** {r.code_cycles_completed}")
        lines.append(f"**Issues addressed:** {len(r.code_fixes_planned)}")
        lines.append(f"**Remaining:** {r.code_remaining}")
        lines.append("")
        lines.append("### Issues Fixed")
        lines.append("")
        lines.append("| Severity | Rule | File | Line | Description |")
        lines.append("|----------|------|------|------|-------------|")
        for fix in r.code_fixes_planned:
            msg = fix.message[:100] + ("..." if len(fix.message) > 100 else "")
            lines.append(
                f"| {fix.severity} | {fix.rule_name} | "
                f"`{fix.file_path}` | {fix.start_line} | {msg} |"
            )
        lines.append("")
        lines.append("### Why These Changes?")
        lines.append("")
        for fix in r.code_fixes_planned:
            lines.append(
                f"- **{fix.rule_name}** in `{fix.file_path}:{fix.start_line}`: "
                f"{fix.message}"
            )
        lines.append("")
    else:
        lines.append("No code security issues found or addressed.")
        lines.append("")

    # --- Files Modified ---
    lines.append("## Files Modified")
    lines.append("")
    unique_files = sorted(set(c.path for c in r.changes))
    if unique_files:
        for f in unique_files:
            lines.append(f"- `{f}`")
    else:
        lines.append("No files were modified.")
    lines.append("")

    # --- Footer ---
    lines.append("---")
    lines.append("*Generated by VIPER — Vulnerability Identification, Patching & Evaluation Robot*")

    report_path.write_text("\n".join(lines))


@app.command()
def auto(
    project_dir: Optional[Path] = typer.Option(None, "--project-dir", "-p", help="Project directory"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Minimum severity"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Path to viper.yaml"),
    max_cycles: int = typer.Option(10, "--max-cycles", "-n", help="Max fix-verify loops"),
    agent_max_iterations: Optional[int] = typer.Option(
        None,
        "--agent-max-iterations",
        help="Override the AI agent tool-use iteration limit for this run",
    ),
    verbose: bool = typer.Option(True, "--verbose/--no-verbose", help="Show details"),
    stream_agent: bool = typer.Option(
        True,
        "--stream-agent/--no-stream-agent",
        help="Stream live agent tool activity during remediation",
    ),
    ai_fix: bool = typer.Option(
        True,
        "--ai-fix/--no-ai-fix",
        help="Use the AI remediation agent (always recommended)",
    ),
    code_scan: bool = typer.Option(
        True,
        "--code-scan/--no-code-scan",
        help="Run Snyk Code (SAST) scan to find and fix source code security issues",
    ),
) -> None:
    """Orchestrated remediation loop: scan -> select fix unit -> fix -> verify -> retry."""
    try:
        cfg = _load_config(config)
        if agent_max_iterations is not None:
            previous_max_iterations = cfg.agent.max_iterations
            cfg.agent.max_iterations = agent_max_iterations
            if cfg.agent.max_no_edit_iterations >= previous_max_iterations:
                cfg.agent.max_no_edit_iterations = agent_max_iterations
        target_dir = project_dir or Path.cwd()
        sev_threshold = _resolve_remediation_severity(severity, cfg)

        console.print(VIPER_BANNER.format(__version__))
        console.print(f"  Project:  [bold]{target_dir}[/bold]")
        console.print(f"  Severity: [bold]{sev_threshold}[/bold]+")
        console.print(f"  Cycles:   [bold]{max_cycles}[/bold] max")
        console.print(f"  AI Fix:   [bold]enabled[/bold] (AI agent handles all remediation)")
        console.print(f"  Agent Steps: [bold]{cfg.agent.max_iterations}[/bold] max per cycle")
        if cfg.agent.max_no_edit_iterations < cfg.agent.max_iterations:
            console.print(
                "  Pre-edit Budget: "
                f"[bold]{cfg.agent.max_no_edit_iterations}[/bold] tool turns before the first file change"
            )
        else:
            console.print(
                "  Pre-edit Budget: [bold]same as total step cap[/bold] "
                "(no early handoff before the full agent budget is used)"
            )
        console.print(f"  Stream:   [bold]{'enabled' if stream_agent else 'disabled'}[/bold]")
        console.print(f"  Code Scan: [bold]{'enabled' if code_scan else 'disabled'}[/bold]")
        console.print()

        from viper.orchestrator import RemediationOrchestrator

        result = RemediationOrchestrator(
            config=cfg,
            project_dir=target_dir,
            severity_threshold=sev_threshold,
            max_cycles=max_cycles,
            use_ai=ai_fix,
            stream_agent=stream_agent,
            verbose=verbose,
            scan_code=code_scan,
        ).run()

        # ── SUMMARY ───────────────────────────────────────────
        elapsed = result.duration_seconds
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)

        summary_table = Table(show_header=False, box=None, padding=(0, 2))
        summary_table.add_column(style="bold")
        summary_table.add_column()
        summary_table.add_row("Dep cycles completed", str(result.cycles_completed))
        summary_table.add_row("Dep vulns fixed", str(result.total_fixed))
        if result.code_cycles_completed > 0:
            summary_table.add_row("Code cycles completed", str(result.code_cycles_completed))
            summary_table.add_row("Code issues fixed", str(result.code_total_fixed))
        summary_table.add_row("Files modified", str(len(result.changes)))
        summary_table.add_row("Duration", f"{minutes}m {seconds}s")

        if result.changes:
            files = "\n".join(f"  {c.path}" for c in result.changes)
            summary_table.add_row("Changed files", files)

        console.print()
        console.print(Panel(summary_table, title="[bold]Summary[/bold]", border_style="cyan"))

        # Generate report.md in the project directory
        report_path = target_dir / "report.md"
        _generate_auto_report(result, report_path)
        console.print(f"\n[green]Report written to:[/green] {report_path}")

    except ViperError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
