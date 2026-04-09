"""Core agent loop — LLM tool-use cycle powered by LiteLLM."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path


# Suppress noisy LiteLLM logs BEFORE importing litellm
logging.getLogger("LiteLLM").setLevel(logging.CRITICAL)
logging.getLogger("litellm").setLevel(logging.CRITICAL)
logging.getLogger("LiteLLM Proxy").setLevel(logging.CRITICAL)
logging.getLogger("LiteLLM Router").setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.CRITICAL)
logging.getLogger("httpcore").setLevel(logging.CRITICAL)
logging.getLogger("openai").setLevel(logging.CRITICAL)

import litellm  # noqa: E402

litellm.suppress_debug_info = True
litellm.set_verbose = False

from rich.console import Console

from viper import ViperAgentError
from viper.agent.prompts import FIX_SYSTEM_PROMPT, FIX_USER_PROMPT, MR_DESCRIPTION_PROMPT
from viper.agent.schemas import TOOL_SCHEMAS
from viper.agent.tools import ToolExecutor
from viper.config import ViperConfig
from viper.models.result import AgentResult, FileChange, ToolCall
from viper.models.vulnerability import SnykReport

console = Console()


class ViperAgent:
    """AI agent that autonomously fixes vulnerabilities using an LLM tool-use loop."""

    def __init__(
        self,
        config: ViperConfig,
        project_dir: Path,
        verbose: bool = False,
    ):
        self.config = config
        self.project_dir = project_dir.resolve()
        self.verbose = verbose
        self.tool_executor = ToolExecutor(
            project_dir=self.project_dir,
            dry_run=config.dry_run,
            blocked_commands=config.agent.blocked_commands,
            timeout=config.agent.timeout_per_tool,
            verbose=verbose,
        )

    @staticmethod
    def _compact_report(report: SnykReport) -> str:
        """Build a compact text summary of the Snyk report to fit in context."""
        from viper.parsers.snyk_parser import SnykParser

        vulns = SnykParser.deduplicate(report.vulnerabilities)
        groups = SnykParser.group_by_package(vulns)

        # Separate upgradable vs non-upgradable
        upgradable_pkgs = {}
        non_upgradable_pkgs = {}
        for pkg_name, pkg_vulns in groups.items():
            if any(v.is_upgradable for v in pkg_vulns):
                upgradable_pkgs[pkg_name] = pkg_vulns
            else:
                non_upgradable_pkgs[pkg_name] = pkg_vulns

        lines = [
            f"Package Manager: {report.package_manager}",
            f"Total Vulnerabilities: {len(vulns)}",
            f"Upgradable: {len(upgradable_pkgs)} packages | Non-upgradable: {len(non_upgradable_pkgs)} packages",
            "",
        ]

        # Upgradable packages first — these are actionable
        if upgradable_pkgs:
            lines.append("ACTION REQUIRED — UPGRADE THESE PACKAGES:")
            lines.append("=" * 60)
            for pkg_name, pkg_vulns in sorted(
                upgradable_pkgs.items(),
                key=lambda x: max(v.severity.rank for v in x[1]),
                reverse=True,
            ):
                version = pkg_vulns[0].version
                max_sev = max(v.severity.value for v in pkg_vulns)

                # Find upgrade target
                upgrade_target = None
                for v in pkg_vulns:
                    for p in v.upgrade_path:
                        if isinstance(p, str) and "@" in p:
                            upgrade_target = p.split("@")[-1]
                            break
                    if upgrade_target:
                        break

                fix_str = f" -> UPGRADE TO {upgrade_target}" if upgrade_target else ""
                lines.append(f"\n  {pkg_name}: {version}{fix_str}  [{max_sev.upper()}]")
                for v in pkg_vulns:
                    lines.append(f"    - {v.title}")

        # Non-upgradable — just list briefly
        if non_upgradable_pkgs:
            lines.append(f"\n\nNON-UPGRADABLE ({len(non_upgradable_pkgs)} packages) — skip these:")
            for pkg_name, pkg_vulns in non_upgradable_pkgs.items():
                max_sev = max(v.severity.value for v in pkg_vulns)
                lines.append(f"  {pkg_name}@{pkg_vulns[0].version} [{max_sev.upper()}]")

        return "\n".join(lines)

    def _pre_scan_project(self, report: SnykReport) -> str:
        """Pre-scan project to build concrete action plan for the agent."""
        import subprocess
        from viper.parsers.snyk_parser import SnykParser
        from viper.agent.tools import IGNORED_DIRS

        vulns = SnykParser.deduplicate(report.vulnerabilities)
        groups = SnykParser.group_by_package(vulns)

        # Find all package.json / requirements.txt / pom.xml files
        dep_files: list[str] = []
        for root, dirs, files in os.walk(self.project_dir):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for f in files:
                if f in ("package.json", "requirements.txt", "pyproject.toml", "pom.xml"):
                    rel = os.path.relpath(os.path.join(root, f), self.project_dir)
                    dep_files.append(rel)

        # Read each dep file and check which vulnerable packages are direct deps
        direct_fixes = []
        transitive_fixes = []

        for pkg_name, pkg_vulns in groups.items():
            if not any(v.is_upgradable for v in pkg_vulns):
                continue

            # Find upgrade target
            upgrade_target = None
            for v in pkg_vulns:
                for p in v.upgrade_path:
                    if isinstance(p, str) and "@" in p:
                        upgrade_target = p.split("@")[-1]
                        break
                if upgrade_target:
                    break

            current_version = pkg_vulns[0].version
            max_sev = max(v.severity.value for v in pkg_vulns).upper()

            # Check which dep files contain this package
            found_in: list[str] = []
            for dep_file in dep_files:
                try:
                    content = (self.project_dir / dep_file).read_text()
                    if f'"{pkg_name}"' in content:
                        found_in.append(dep_file)
                except OSError:
                    pass

            if found_in:
                for f in found_in:
                    direct_fixes.append({
                        "package": pkg_name,
                        "current": current_version,
                        "target": upgrade_target or "latest",
                        "file": f,
                        "severity": max_sev,
                    })
            else:
                transitive_fixes.append({
                    "package": pkg_name,
                    "current": current_version,
                    "target": upgrade_target or "latest",
                    "severity": max_sev,
                })

        # Build action plan text
        lines = [f"DEPENDENCY FILES FOUND: {', '.join(dep_files)}", ""]

        if direct_fixes:
            lines.append("DIRECT DEPENDENCY FIXES (edit the version in the file):")
            for fix in direct_fixes:
                lines.append(
                    f'  1. create_backup("{fix["file"]}")'
                )
                lines.append(
                    f'  2. edit_file("{fix["file"]}", '
                    f'old containing "{fix["package"]}": "{fix["current"]}", '
                    f'new "{fix["package"]}": "{fix["target"]}")'
                )
                lines.append(f'     [{fix["severity"]}] {fix["package"]} {fix["current"]} -> {fix["target"]}')
                lines.append("")

        if transitive_fixes:
            root_pkg = next((f for f in dep_files if f == "package.json"), dep_files[0] if dep_files else "package.json")
            lines.append("TRANSITIVE DEPENDENCY FIXES (add npm overrides):")
            lines.append(f'  File: {root_pkg}')
            lines.append(f'  1. create_backup("{root_pkg}")')
            lines.append(f'  2. read_file("{root_pkg}") to check if "overrides" section exists')
            lines.append(f'  3. edit_file to add/update overrides:')
            for fix in transitive_fixes:
                lines.append(f'     "{fix["package"]}": "^{fix["target"]}"  [{fix["severity"]}]')
            lines.append("")

        if not direct_fixes and not transitive_fixes:
            lines.append("NO UPGRADABLE VULNERABILITIES FOUND. Call done() immediately.")

        return "\n".join(lines)

    async def run_fix(self, report: SnykReport) -> AgentResult:
        """Run the agent to fix vulnerabilities in the project."""
        compact = self._compact_report(report)
        action_plan = self._pre_scan_project(report)

        system_prompt = FIX_SYSTEM_PROMPT.format(
            snyk_report=compact,
            project_dir=str(self.project_dir),
        )

        # The user message now includes the concrete action plan
        user_msg = FIX_USER_PROMPT + "\n\nACTION PLAN (pre-computed):\n" + action_plan

        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ]

        all_tool_calls: list[ToolCall] = []
        has_made_edits = False
        text_only_count = 0

        for iteration in range(self.config.agent.max_iterations):
            if self.verbose:
                console.print(f"\n[cyan]--- Agent iteration {iteration + 1} ---[/cyan]")

            # Force tool use until the agent has actually edited files or
            # explicitly called done(). This prevents it from just reading
            # files and then responding with text.
            if not has_made_edits and not self.tool_executor.is_done:
                tool_choice = "required"
            else:
                tool_choice = "auto"

            try:
                response = await litellm.acompletion(
                    model=self.config.ai.model,
                    messages=messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice=tool_choice,
                    temperature=self.config.ai.temperature,
                    max_tokens=self.config.ai.max_tokens,
                )
            except Exception as e:
                raise ViperAgentError(f"LLM call failed: {e}")

            choice = response.choices[0]
            message = choice.message

            # Append assistant message to conversation
            messages.append(message.model_dump(exclude_none=True))

            # If no tool calls, check if we should stop or nudge
            if not message.tool_calls:
                text_only_count += 1

                # Only stop if agent has made edits or called done()
                if has_made_edits or self.tool_executor.is_done:
                    if self.verbose:
                        console.print(f"[green]Agent finished[/green]")
                    return AgentResult(
                        success=True,
                        summary=message.content or "Changes applied.",
                        iterations_used=iteration + 1,
                        tool_calls=all_tool_calls,
                        changes=[
                            FileChange(path=c["path"])
                            for c in self.tool_executor.changes
                        ],
                    )

                # Give up after 3 text-only responses with no edits
                if text_only_count >= 3:
                    return AgentResult(
                        success=False,
                        summary=message.content or "Agent failed to make changes.",
                        iterations_used=iteration + 1,
                        tool_calls=all_tool_calls,
                        changes=[],
                    )

                # Nudge the agent to actually edit files
                messages.append({
                    "role": "user",
                    "content": (
                        "You have not edited any files yet. You MUST call `edit_file` to "
                        "fix vulnerabilities. If the vulnerable package is not a direct "
                        "dependency, add an npm overrides section to package.json to force "
                        "the transitive dependency to a safe version. If you truly cannot "
                        "fix it, call `done()` with an explanation. Do NOT just read files "
                        "— take action NOW."
                    ),
                })
                continue

            # Execute each tool call
            text_only_count = 0
            for tool_call in message.tool_calls:
                fn = tool_call.function
                tool_name = fn.name
                try:
                    arguments = json.loads(fn.arguments)
                except json.JSONDecodeError:
                    arguments = {}

                if self.verbose:
                    args_preview = json.dumps(arguments, indent=2)
                    if len(args_preview) > 300:
                        args_preview = args_preview[:300] + "..."
                    console.print(f"  [yellow]Tool:[/yellow] {tool_name}({args_preview})")

                result = self.tool_executor.execute(tool_name, arguments)

                all_tool_calls.append(
                    ToolCall(
                        tool_name=tool_name,
                        arguments=arguments,
                        result=result[:1000],  # Truncate for storage
                        iteration=iteration,
                    )
                )

                # Track if agent has made actual file modifications
                if tool_name in ("edit_file", "write_file") and "Error" not in result:
                    has_made_edits = True

                # Append tool result to conversation
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })

                # Check if agent called done()
                if self.tool_executor.is_done:
                    done_data = self.tool_executor.done_result or {}
                    return AgentResult(
                        success=True,
                        summary=done_data.get("summary", ""),
                        tests_passed=done_data.get("tests_passed"),
                        iterations_used=iteration + 1,
                        tool_calls=all_tool_calls,
                        changes=[
                            FileChange(path=c["path"])
                            for c in done_data.get("changes", self.tool_executor.changes)
                        ],
                    )

        # Hit max iterations
        return AgentResult(
            success=False,
            summary=f"Agent reached max iterations ({self.config.agent.max_iterations}) without completing.",
            iterations_used=self.config.agent.max_iterations,
            tool_calls=all_tool_calls,
            changes=[
                FileChange(path=c["path"])
                for c in self.tool_executor.changes
            ],
        )

    async def generate_mr_description(
        self, result: AgentResult, report: SnykReport
    ) -> str:
        """Generate a merge request description using the LLM."""
        changes_summary = result.summary
        vulns_summary = "\n".join(
            f"- [{v.severity.value.upper()}] {v.package_name}@{v.version}: {v.title}"
            for v in report.vulnerabilities
        )
        test_results = (
            "Passed" if result.tests_passed else "Failed" if result.tests_passed is False else "Not run"
        )

        prompt = MR_DESCRIPTION_PROMPT.format(
            changes_summary=changes_summary,
            vulns_summary=vulns_summary,
            test_results=test_results,
        )

        try:
            response = await litellm.acompletion(
                model=self.config.ai.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=2000,
            )
            return response.choices[0].message.content or ""
        except Exception:
            # Fallback to basic description
            return (
                f"## VIPER Vulnerability Fix\n\n"
                f"### Summary\n{changes_summary}\n\n"
                f"### Vulnerabilities Addressed\n{vulns_summary}\n\n"
                f"### Tests\n{test_results}"
            )
