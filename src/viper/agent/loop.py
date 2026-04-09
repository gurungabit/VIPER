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

    def _compact_report(self, report: SnykReport) -> str:
        """Build a compact, strategic summary of the Snyk report to fit in context."""
        from viper.parsers.snyk_parser import SnykParser
        from viper.fixer import DirectFixer

        vulns = SnykParser.deduplicate(report.vulnerabilities)
        planned_actions = DirectFixer(
            project_dir=self.project_dir,
            dry_run=True,
            verbose=False,
        )._plan_fixes(report)
        non_upgradable = [v for v in vulns if not v.is_upgradable]

        lines = [
            f"Package Manager: {report.package_manager}",
            f"Total Vulnerabilities: {len(vulns)}",
            f"Actionable Fix Candidates: {len(planned_actions)} | Non-upgradable Occurrences: {len(non_upgradable)}",
            "",
        ]

        if planned_actions:
            lines.append("STRATEGIC FIX CANDIDATES:")
            lines.append("=" * 60)
            severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            for action in sorted(
                planned_actions,
                key=lambda item: (
                    severity_rank.get(item.severity, 0),
                    item.file_path,
                    item.package,
                ),
                reverse=True,
            ):
                lines.append(
                    f"- [{action.severity}] {action.package}@{action.current_version}"
                    f" -> {action.fix_version} | file={action.file_path}"
                    f" | mode={'direct' if action.is_direct else 'override'}"
                )

        if non_upgradable:
            lines.append(f"\nNON-UPGRADABLE OR MANUAL ({len(non_upgradable)} occurrences):")
            for vuln in sorted(non_upgradable, key=lambda item: item.severity.rank, reverse=True)[:20]:
                location = vuln.display_target_file or vuln.source_project_name or "unknown target"
                lines.append(
                    f"- [{vuln.severity.value.upper()}] {vuln.package_name}@{vuln.version}"
                    f" | target={location} | id={vuln.id}"
                )

        return "\n".join(lines)

    @staticmethod
    def _matching_upgrade_target(vuln) -> str | None:
        """Return the upgrade target for the vulnerable package itself, if present."""
        for path_entry in vuln.upgrade_path:
            if not isinstance(path_entry, str) or "@" not in path_entry:
                continue
            dep_name, version = path_entry.rsplit("@", 1)
            if dep_name == vuln.package_name:
                return version
        return None

    def _pre_scan_project(self, report: SnykReport) -> str:
        """Build repository hints without prescribing exact edits."""
        from viper.parsers.snyk_parser import SnykParser
        from viper.agent.tools import IGNORED_DIRS
        from viper.fixer import DirectFixer

        vulns = SnykParser.deduplicate(report.vulnerabilities)
        planned_actions = DirectFixer(
            project_dir=self.project_dir,
            dry_run=True,
            verbose=False,
        )._plan_fixes(report)

        dep_files: list[str] = []
        for root, dirs, files in os.walk(self.project_dir):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for f in files:
                if f in ("package.json", "requirements.txt", "pyproject.toml", "pom.xml"):
                    rel = os.path.relpath(os.path.join(root, f), self.project_dir)
                    dep_files.append(rel)

        lines = [f"DEPENDENCY FILES FOUND: {', '.join(dep_files) if dep_files else '(none)'}", ""]

        if planned_actions:
            lines.append("REPO HINTS (verify with tools before editing):")
            for action in planned_actions:
                method = "direct version bump" if action.is_direct else "override"
                lines.append(
                    f"- {action.package}: {action.current_version} -> {action.fix_version}"
                    f" | file={action.file_path} | suggested={method}"
                )
            lines.append("")

        remaining_manual = []
        action_keys = {
            (action.package, action.file_path, action.fix_version)
            for action in planned_actions
        }
        for vuln in vulns:
            target = self._matching_upgrade_target(vuln)
            location = vuln.display_target_file or vuln.source_project_name or ""
            if not vuln.is_upgradable:
                remaining_manual.append(
                    f"- {vuln.package_name}@{vuln.version} [{vuln.severity.value.upper()}]"
                    f" | target={location or 'unknown'} | manual/no direct fix target"
                )
                continue

            if location and (vuln.package_name, location, target or "") not in action_keys:
                remaining_manual.append(
                    f"- {vuln.package_name}@{vuln.version} [{vuln.severity.value.upper()}]"
                    f" | target={location} | inspect ownership manually"
                )

        if remaining_manual:
            lines.append("ITEMS THAT MAY REQUIRE EXTRA INSPECTION:")
            lines.extend(remaining_manual[:20])
            lines.append("")

        lines.append(
            "Use tools to inspect manifests, lockfiles, workspace layout, and dependency trees before deciding on direct bumps or overrides."
        )
        lines.append(
            "Good starting commands include `npm ls <package>`, `npm ls --all`, `npm test`, and scoped installs run from the correct subproject or workspace root."
        )

        return "\n".join(lines)

    async def run_fix(self, report: SnykReport) -> AgentResult:
        """Run the agent to fix vulnerabilities in the project."""
        compact = self._compact_report(report)
        action_plan = self._pre_scan_project(report)

        system_prompt = FIX_SYSTEM_PROMPT.format(
            snyk_report=compact,
            project_dir=str(self.project_dir),
        )

        user_msg = FIX_USER_PROMPT + "\n\nREPO HINTS:\n" + action_plan

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
