"""VIPER CLI — Vulnerability Identification, Patching & Evaluation Robot."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
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


def _load_config(config_path: Path | None) -> ViperConfig:
    if config_path:
        return ViperConfig.load(config_path)
    # Check default locations
    for p in [Path("viper.yaml"), Path("viper.yml")]:
        if p.exists():
            return ViperConfig.load(p)
    return ViperConfig()


def _get_report(
    project_dir: Path | None,
    report_file: Path | None,
    config: ViperConfig,
    severity: str | None,
) -> SnykReport:
    """Run Snyk scan or load existing report."""
    if report_file:
        return SnykParser.parse_file(report_file)

    if not project_dir:
        project_dir = Path.cwd()

    return SnykParser.run_scan(
        project_dir=project_dir,
        snyk_token=config.snyk.token or None,
        org=config.snyk.org or None,
        severity_threshold=severity or config.severity_threshold,
    )


def _display_vulns(report: SnykReport, severity_filter: str | None = None) -> None:
    """Display vulnerabilities in a Rich table."""
    vulns = report.vulnerabilities
    if severity_filter:
        min_sev = Severity(severity_filter)
        vulns = [v for v in vulns if v.severity >= min_sev]

    vulns = SnykParser.deduplicate(vulns)

    if not vulns:
        console.print("[green]No vulnerabilities found![/green]")
        return

    table = Table(title=f"Vulnerabilities ({len(vulns)} found)")
    table.add_column("Severity", style="bold")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Title")
    table.add_column("Upgradable")
    table.add_column("ID", style="dim")

    severity_colors = {
        Severity.critical: "red",
        Severity.high: "bright_red",
        Severity.medium: "yellow",
        Severity.low: "blue",
    }

    for v in sorted(vulns, key=lambda x: x.severity.rank, reverse=True):
        color = severity_colors.get(v.severity, "white")
        table.add_row(
            f"[{color}]{v.severity.value.upper()}[/{color}]",
            v.package_name,
            v.version,
            v.title,
            "Yes" if v.is_upgradable else "No",
            v.id,
        )

    console.print(table)

    # Summary
    by_sev = {}
    for v in vulns:
        by_sev[v.severity.value] = by_sev.get(v.severity.value, 0) + 1
    summary_parts = [f"{count} {sev}" for sev, count in sorted(by_sev.items(), key=lambda x: Severity(x[0]).rank, reverse=True)]
    console.print(f"\nSummary: {', '.join(summary_parts)}")


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
        report = _get_report(project_dir, report_file, cfg, severity)

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
    no_test: bool = typer.Option(False, "--no-test", help="Skip running tests after fix"),
    verbose: bool = typer.Option(False, "--verbose", help="Show agent tool calls"),
    max_iterations: Optional[int] = typer.Option(None, "--max-iterations", help="Max agent loop iterations"),
) -> None:
    """Analyze and fix vulnerabilities using AI agent."""
    try:
        cfg = _load_config(config)
        if dry_run:
            cfg.dry_run = True
        if max_iterations:
            cfg.agent.max_iterations = max_iterations

        report = _get_report(project_dir, report_file, cfg, severity)

        if report.ok and not report.vulnerabilities:
            console.print("[green]No vulnerabilities found![/green]")
            raise typer.Exit()

        _display_vulns(report, severity)

        target_dir = project_dir or Path.cwd()

        from viper.agent.loop import ViperAgent

        agent = ViperAgent(config=cfg, project_dir=target_dir, verbose=verbose)
        result = asyncio.run(agent.run_fix(report))

        if result.success:
            console.print(f"\n[green]Fix complete![/green] {result.summary}")
            if result.tests_passed is not None:
                status = "[green]passed[/green]" if result.tests_passed else "[red]failed[/red]"
                console.print(f"Tests: {status}")
            for change in result.changes:
                console.print(f"  Modified: {change.path}")
        else:
            console.print(f"\n[red]Fix failed:[/red] {result.summary}")
            raise typer.Exit(1)

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
        snyk_report = _get_report(project_dir, report_file, cfg, severity)

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
    dry_run: bool = typer.Option(False, "--dry-run", help="Show changes without creating MR"),
    verbose: bool = typer.Option(False, "--verbose", help="Show agent tool calls"),
) -> None:
    """Fix vulnerabilities and create a GitLab merge request."""
    try:
        cfg = _load_config(config)
        if dry_run:
            cfg.dry_run = True
        if target_branch:
            cfg.gitlab.target_branch = target_branch

        report = _get_report(project_dir, report_file, cfg, severity)

        if report.ok and not report.vulnerabilities:
            console.print("[green]No vulnerabilities found![/green]")
            raise typer.Exit()

        target_dir = project_dir or Path.cwd()

        from viper.agent.loop import ViperAgent

        agent = ViperAgent(config=cfg, project_dir=target_dir, verbose=verbose)
        result = asyncio.run(agent.run_fix(report))

        if not result.success:
            console.print(f"[red]Fix failed:[/red] {result.summary}")
            raise typer.Exit(1)

        if cfg.dry_run:
            console.print("[yellow]Dry run — skipping MR creation[/yellow]")
            console.print(result.summary)
            raise typer.Exit()

        from viper.gitlab_integration import GitLabClient

        gl = GitLabClient(cfg.gitlab)
        mr_url = asyncio.run(gl.create_fix_mr(result, report))
        console.print(f"\n[green]Merge request created:[/green] {mr_url}")

    except ViperError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
