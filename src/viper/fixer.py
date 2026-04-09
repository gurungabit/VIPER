"""Direct vulnerability fixer — applies Snyk-recommended versions without LLM."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from viper.agent.tools import IGNORED_DIRS
from viper.models.result import AgentResult, FileChange
from viper.models.vulnerability import SnykReport
from viper.parsers.snyk_parser import SnykParser

console = Console()


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    """Parse a semver string into (major, minor, patch). Returns None if invalid."""
    # Strip leading v, ^, ~, >=, etc.
    cleaned = re.sub(r'^[v^~>=<]*', '', version.strip())
    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', cleaned)
    if not match:
        return None
    return (
        int(match.group(1)),
        int(match.group(2) or 0),
        int(match.group(3) or 0),
    )


def _is_safe_upgrade(current: str, target: str) -> tuple[bool, str]:
    """Check if upgrading from current to target is safe.

    Returns (is_safe, reason).
    Rules:
    - NEVER downgrade (target major.minor.patch must be >= current)
    - NEVER cross major versions (e.g. 8.x -> 4.x)
    """
    cur = _parse_semver(current)
    tgt = _parse_semver(target)

    if cur is None or tgt is None:
        return False, f"cannot parse versions: {current} -> {target}"

    # Never downgrade
    if tgt < cur:
        return False, f"BLOCKED: would downgrade {current} -> {target}"

    # Same version = no-op
    if tgt == cur:
        return False, f"already at {current}"

    # Warn on major version change
    if tgt[0] != cur[0]:
        return False, f"BLOCKED: major version change {current} -> {target} (v{cur[0]} -> v{tgt[0]})"

    return True, "ok"


@dataclass
class FixAction:
    package: str
    current_version: str
    fix_version: str
    severity: str
    file_path: str
    is_direct: bool
    vuln_ids: list[str] = field(default_factory=list)


class DirectFixer:
    """Applies Snyk-recommended fixes directly — no LLM needed."""

    def __init__(self, project_dir: Path, dry_run: bool = False, verbose: bool = False):
        self.project_dir = project_dir.resolve()
        self.dry_run = dry_run
        self.verbose = verbose
        self._backups: list[Path] = []
        self._changes: list[FileChange] = []

    def fix(self, report: SnykReport) -> AgentResult:
        """Analyze and apply all upgradable fixes."""
        actions = self._plan_fixes(report)

        if not actions:
            return AgentResult(
                success=True,
                summary="No upgradable vulnerabilities found.",
                changes=[],
                iterations_used=0,
            )

        # Group actions by file
        by_file: dict[str, list[FixAction]] = {}
        for a in actions:
            by_file.setdefault(a.file_path, []).append(a)

        applied = []
        skipped = []

        for file_path, file_actions in by_file.items():
            full_path = self.project_dir / file_path
            if not full_path.exists():
                for a in file_actions:
                    skipped.append(f"{a.package}: file {file_path} not found")
                continue

            # Backup
            if not self.dry_run:
                backup = full_path.with_suffix(full_path.suffix + ".viper.bak")
                shutil.copy2(full_path, backup)
                self._backups.append(backup)

            content = full_path.read_text()
            original = content

            for action in file_actions:
                if action.is_direct:
                    new_content = self._apply_direct_fix(content, action, file_path)
                else:
                    new_content = self._apply_override_fix(content, action, file_path)

                if new_content and new_content != content:
                    content = new_content
                    applied.append(action)
                    method = "direct" if action.is_direct else "override"
                    if self.verbose:
                        console.print(
                            f"  [green]{action.package}: "
                            f"{action.current_version} -> {action.fix_version} "
                            f"in {file_path} ({method})[/green]"
                        )
                else:
                    if self.verbose:
                        method = "direct edit" if action.is_direct else "override"
                        console.print(
                            f"  [yellow]Skip {action.package}: "
                            f"could not apply {method} in {file_path}[/yellow]"
                        )
                    skipped.append(
                        f"{action.package}: could not apply in {file_path}"
                    )

            if content != original and not self.dry_run:
                full_path.write_text(content)
                self._changes.append(FileChange(path=file_path))

        # Run npm install if we changed any package.json
        install_ok = True
        if not self.dry_run and self._changes:
            install_ok = self._run_install(by_file)

        # Build summary
        summary_parts = []
        if applied:
            summary_parts.append(f"Upgraded {len(applied)} packages:")
            for a in applied:
                summary_parts.append(
                    f"  [{a.severity}] {a.package}: {a.current_version} -> {a.fix_version}"
                )
        if skipped:
            summary_parts.append(f"\nSkipped {len(skipped)}:")
            for s in skipped:
                summary_parts.append(f"  {s}")
        if not install_ok:
            summary_parts.append("\nWARNING: npm install had errors (see above)")

        return AgentResult(
            success=len(applied) > 0,
            summary="\n".join(summary_parts),
            changes=self._changes,
            tests_passed=None,
            iterations_used=1,
        )

    def _plan_fixes(self, report: SnykReport) -> list[FixAction]:
        """Build list of fix actions from the Snyk report."""
        vulns = SnykParser.deduplicate(report.vulnerabilities)
        groups = SnykParser.group_by_package(vulns)

        # Find all dependency files
        dep_files = self._find_dep_files()

        actions = []
        seen_packages: set[str] = set()

        for pkg_name, pkg_vulns in groups.items():
            if not any(v.is_upgradable for v in pkg_vulns):
                continue
            if pkg_name in seen_packages:
                continue
            seen_packages.add(pkg_name)

            # Find fix version — must match the vulnerable package name
            fix_version = None
            for v in pkg_vulns:
                for p in v.upgrade_path:
                    if isinstance(p, str) and "@" in p:
                        # upgrade_path entries are like "package@version"
                        # Only use it if it's for THIS package
                        parts = p.rsplit("@", 1)
                        if len(parts) == 2 and parts[0] == pkg_name:
                            fix_version = parts[1]
                            break
                if fix_version:
                    break

            if not fix_version:
                continue

            current = pkg_vulns[0].version
            max_sev = max(v.severity.value for v in pkg_vulns).upper()
            vuln_ids = [v.id for v in pkg_vulns]

            # Validate the upgrade is safe
            safe, reason = _is_safe_upgrade(current, fix_version)
            if not safe:
                if self.verbose:
                    console.print(f"  [yellow]Skip {pkg_name}:[/yellow] {reason}")
                continue

            # Check if DIRECT dependency (in dependencies/devDependencies)
            found_in = []
            for dep_file in dep_files:
                try:
                    if dep_file.endswith(".json"):
                        data = json.loads((self.project_dir / dep_file).read_text())
                        deps = data.get("dependencies", {})
                        dev_deps = data.get("devDependencies", {})
                        if pkg_name in deps or pkg_name in dev_deps:
                            found_in.append(dep_file)
                    else:
                        # requirements.txt, pom.xml — simple text check
                        content = (self.project_dir / dep_file).read_text()
                        if pkg_name in content:
                            found_in.append(dep_file)
                except (OSError, json.JSONDecodeError):
                    pass

            if found_in:
                for f in found_in:
                    actions.append(FixAction(
                        package=pkg_name,
                        current_version=current,
                        fix_version=fix_version,
                        severity=max_sev,
                        file_path=f,
                        is_direct=True,
                        vuln_ids=vuln_ids,
                    ))
            else:
                # Transitive — add override to the nearest package.json
                # Try to find which sub-project this vuln belongs to using
                # the Snyk "from" path (first entry is the project name)
                target_pkg = None
                for v in pkg_vulns:
                    if v.from_path:
                        # from_path[0] is like "project-name@version"
                        project_id = v.from_path[0].rsplit("@", 1)[0] if v.from_path[0] else ""
                        # Find the package.json whose "name" matches
                        for df in dep_files:
                            if not df.endswith("package.json"):
                                continue
                            try:
                                d = json.loads((self.project_dir / df).read_text())
                                if d.get("name", "") == project_id:
                                    target_pkg = df
                                    break
                            except (OSError, json.JSONDecodeError):
                                pass
                    if target_pkg:
                        break

                if not target_pkg:
                    target_pkg = next(
                        (f for f in dep_files if f == "package.json"),
                        dep_files[0] if dep_files else "package.json",
                    )

                actions.append(FixAction(
                    package=pkg_name,
                    current_version=current,
                    fix_version=fix_version,
                    severity=max_sev,
                    file_path=target_pkg,
                    is_direct=False,
                    vuln_ids=vuln_ids,
                ))

        return actions

    def _find_dep_files(self) -> list[str]:
        """Find all dependency files in the project."""
        dep_files = []
        for root, dirs, files in os.walk(self.project_dir):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for f in files:
                if f in ("package.json", "requirements.txt", "pyproject.toml", "pom.xml"):
                    rel = os.path.relpath(os.path.join(root, f), self.project_dir)
                    dep_files.append(rel)
        return dep_files

    def _apply_direct_fix(
        self, content: str, action: FixAction, file_path: str
    ) -> str | None:
        """Update a direct dependency version in the file content."""
        # Double-check: never downgrade or cross major versions
        safe, reason = _is_safe_upgrade(action.current_version, action.fix_version)
        if not safe:
            if self.verbose:
                console.print(f"  [red]BLOCKED {action.package}:[/red] {reason}")
            return None

        if file_path.endswith(".json"):
            # Try exact match: "package": "version"
            # Handle various version prefixes: ^, ~, >=, etc.
            import re

            pattern = re.compile(
                rf'("{re.escape(action.package)}"\s*:\s*")([^"]*{re.escape(action.current_version)}[^"]*)"'
            )
            match = pattern.search(content)
            if match:
                prefix = match.group(1)
                old_ver = match.group(2)
                # Preserve version prefix (^, ~, etc.)
                ver_prefix = ""
                for p in ("^", "~", ">=", ">", "<=", "<", "="):
                    if old_ver.startswith(p):
                        ver_prefix = p
                        break
                new_ver_str = f"{ver_prefix}{action.fix_version}"
                return content[:match.start()] + f'{prefix}{new_ver_str}"' + content[match.end():]

        elif file_path.endswith(".txt"):
            # requirements.txt: package==version
            old = f"{action.package}=={action.current_version}"
            new = f"{action.package}=={action.fix_version}"
            if old in content:
                return content.replace(old, new)

        elif file_path.endswith(".xml"):
            # pom.xml — more complex, skip for now
            pass

        return None

    def _apply_override_fix(
        self, content: str, action: FixAction, file_path: str
    ) -> str | None:
        """Add an npm override for a transitive dependency."""
        # Double-check: never downgrade or cross major versions
        safe, reason = _is_safe_upgrade(action.current_version, action.fix_version)
        if not safe:
            if self.verbose:
                console.print(f"  [red]BLOCKED override {action.package}:[/red] {reason}")
            return None

        if not file_path.endswith(".json"):
            return None

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None

        overrides = data.get("overrides", {})
        overrides[action.package] = f"^{action.fix_version}"
        data["overrides"] = overrides

        return json.dumps(data, indent=2) + "\n"

    def _run_install(self, by_file: dict[str, list[FixAction]]) -> bool:
        """Run package install commands for modified files."""
        success = True

        # Find unique directories with modified package.json files
        pkg_dirs: set[str] = set()
        for file_path in by_file:
            if file_path.endswith("package.json"):
                pkg_dir = str((self.project_dir / file_path).parent)
                pkg_dirs.add(pkg_dir)

        for pkg_dir in pkg_dirs:
            if self.verbose:
                console.print(f"  Running npm install in {pkg_dir}...")
            try:
                result = subprocess.run(
                    ["npm", "install", "--package-lock-only"],
                    cwd=pkg_dir,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0 and self.verbose:
                    console.print(f"  [yellow]npm install warning:[/yellow] {result.stderr[:200]}")
                    success = False
            except Exception as e:
                if self.verbose:
                    console.print(f"  [red]npm install failed:[/red] {e}")
                success = False

        return success
