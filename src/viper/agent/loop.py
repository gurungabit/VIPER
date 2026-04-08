"""Core agent loop — LLM tool-use cycle powered by LiteLLM."""

from __future__ import annotations

import json
from pathlib import Path

import litellm
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
        # Group by package to compress duplicates
        groups = SnykParser.group_by_package(vulns)

        lines = [
            f"Package Manager: {report.package_manager}",
            f"Total Dependencies: {report.dependency_count}",
            f"Unique Vulnerabilities: {len(vulns)}",
            f"Affected Packages: {len(groups)}",
            "",
            "VULNERABILITIES BY PACKAGE:",
            "=" * 60,
        ]

        for pkg_name, pkg_vulns in sorted(
            groups.items(),
            key=lambda x: max(v.severity.rank for v in x[1]),
            reverse=True,
        ):
            version = pkg_vulns[0].version
            max_sev = max(v.severity.value for v in pkg_vulns)
            upgradable = any(v.is_upgradable for v in pkg_vulns)

            # Find upgrade target from upgrade_path
            upgrade_target = None
            for v in pkg_vulns:
                for p in v.upgrade_path:
                    if isinstance(p, str) and "@" in p:
                        upgrade_target = p.split("@")[-1]
                        break
                if upgrade_target:
                    break

            lines.append(f"\n{pkg_name}@{version}")
            lines.append(f"  Severity: {max_sev.upper()} | Upgradable: {'Yes' if upgradable else 'No'}")
            if upgrade_target:
                lines.append(f"  Suggested upgrade: {pkg_name}@{upgrade_target}")

            for v in pkg_vulns:
                lines.append(f"  - [{v.severity.value.upper()}] {v.title} ({v.id})")
                if v.cvss_score:
                    lines.append(f"    CVSS: {v.cvss_score}")

        return "\n".join(lines)

    async def run_fix(self, report: SnykReport) -> AgentResult:
        """Run the agent to fix vulnerabilities in the project."""
        # Build compact report to fit within LLM context limits
        compact = self._compact_report(report)
        system_prompt = FIX_SYSTEM_PROMPT.format(
            snyk_report=compact,
            project_dir=str(self.project_dir),
        )

        messages: list[dict] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": FIX_USER_PROMPT},
        ]

        all_tool_calls: list[ToolCall] = []

        for iteration in range(self.config.agent.max_iterations):
            if self.verbose:
                console.print(f"\n[cyan]--- Agent iteration {iteration + 1} ---[/cyan]")

            try:
                response = await litellm.acompletion(
                    model=self.config.ai.model,
                    messages=messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=self.config.ai.temperature,
                    max_tokens=self.config.ai.max_tokens,
                )
            except Exception as e:
                raise ViperAgentError(f"LLM call failed: {e}")

            choice = response.choices[0]
            message = choice.message

            # Append assistant message to conversation
            messages.append(message.model_dump(exclude_none=True))

            # If no tool calls, the agent is done (text response only)
            if not message.tool_calls:
                if self.verbose:
                    console.print(f"[green]Agent finished with text response[/green]")

                return AgentResult(
                    success=True,
                    summary=message.content or "No changes needed.",
                    iterations_used=iteration + 1,
                    tool_calls=all_tool_calls,
                    changes=[
                        FileChange(path=c["path"])
                        for c in self.tool_executor.changes
                    ],
                )

            # Execute each tool call
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
