"""GitLab API integration for creating merge requests."""

from __future__ import annotations

from datetime import datetime

import httpx

from viper import ViperGitLabError
from viper.config import GitLabConfig
from viper.models.result import AgentResult
from viper.models.vulnerability import SnykReport


class GitLabClient:
    """Manages GitLab API interactions for VIPER merge requests."""

    def __init__(self, config: GitLabConfig):
        self.config = config
        self.base_url = f"{config.url.rstrip('/')}/api/v4"
        self.headers = {"PRIVATE-TOKEN": config.token}

    async def _request(
        self, method: str, path: str, json: dict | None = None
    ) -> dict:
        """Make an authenticated request to the GitLab API."""
        url = f"{self.base_url}/projects/{self.config.project_id}{path}"
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.request(
                method, url, headers=self.headers, json=json
            )
            if response.status_code >= 400:
                raise ViperGitLabError(
                    f"GitLab API error ({response.status_code}): {response.text}"
                )
            return response.json()

    async def create_branch(self, branch_name: str, ref: str = "main") -> dict:
        """Create a new branch."""
        return await self._request(
            "POST",
            "/repository/branches",
            json={"branch": branch_name, "ref": ref},
        )

    async def commit_changes(
        self,
        branch: str,
        message: str,
        file_changes: list[dict],
    ) -> dict:
        """Commit file changes to a branch.

        file_changes: list of {"file_path": str, "content": str}
        """
        actions = [
            {
                "action": "update",
                "file_path": change["file_path"],
                "content": change["content"],
            }
            for change in file_changes
        ]
        return await self._request(
            "POST",
            "/repository/commits",
            json={
                "branch": branch,
                "commit_message": message,
                "actions": actions,
            },
        )

    async def create_merge_request(
        self,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str,
        labels: list[str] | None = None,
    ) -> dict:
        """Create a merge request."""
        data: dict = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description,
            "remove_source_branch": True,
        }
        if labels:
            data["labels"] = ",".join(labels)
        return await self._request("POST", "/merge_requests", json=data)

    async def create_fix_mr(
        self, result: AgentResult, report: SnykReport
    ) -> str:
        """Full workflow: create branch, commit changes, create MR. Returns MR URL."""
        # Determine ecosystem from report
        ecosystem = report.package_manager or "deps"
        date_str = datetime.now().strftime("%Y-%m-%d")
        branch_name = f"viper/fix-{ecosystem}-vulns-{date_str}"

        # Create branch
        try:
            await self.create_branch(branch_name, self.config.target_branch)
        except ViperGitLabError as e:
            if "already exists" not in str(e).lower():
                raise

        # Read changed files and commit
        from pathlib import Path

        file_changes = []
        for change in result.changes:
            fpath = Path(change.path)
            if fpath.exists():
                file_changes.append({
                    "file_path": change.path,
                    "content": fpath.read_text(),
                })

        if file_changes:
            vuln_count = len(report.vulnerabilities)
            await self.commit_changes(
                branch=branch_name,
                message=f"fix: resolve {vuln_count} security vulnerabilities\n\nAutomated by VIPER",
                file_changes=file_changes,
            )

        # Generate MR description
        from viper.agent.loop import ViperAgent

        description = (
            f"## VIPER Automated Security Fix\n\n"
            f"{result.summary}\n\n"
            f"### Vulnerabilities Addressed\n"
        )
        for v in report.vulnerabilities:
            description += f"- **[{v.severity.value.upper()}]** {v.package_name}@{v.version}: {v.title}\n"

        if result.tests_passed is not None:
            status = "Passed" if result.tests_passed else "Failed"
            description += f"\n### Tests\n{status}\n"

        # Create MR
        vuln_count = len(report.vulnerabilities)
        mr_data = await self.create_merge_request(
            source_branch=branch_name,
            target_branch=self.config.target_branch,
            title=f"[VIPER] Fix {vuln_count} security vulnerabilities",
            description=description,
            labels=["security", "automated", "viper"],
        )

        return mr_data.get("web_url", mr_data.get("url", "MR created"))
