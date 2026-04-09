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
from viper.models.vulnerability import Severity, SnykReport
from viper.parsers.snyk_parser import SnykParser

console = Console()

PACKAGE_JSON_DEP_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
PACKAGE_LOCK_FILES = ("package-lock.json", "npm-shrinkwrap.json")


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


def _severity_rank(value: str) -> int:
    """Map a severity string to its numeric rank."""
    return Severity(value.lower()).rank


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

        applied: list[FixAction] = []
        refreshed: list[FixAction] = []
        skipped: list[str] = []
        install_targets: set[str] = set()

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
                    install_targets.add(file_path)
                    method = "direct" if action.is_direct else "override"
                    if self.verbose:
                        console.print(
                            f"  [green]{action.package}: "
                            f"{action.current_version} -> {action.fix_version} "
                            f"in {file_path} ({method})[/green]"
                        )
                elif self._action_already_present(content, action, file_path):
                    refreshed.append(action)
                    install_targets.add(file_path)
                    if self.verbose:
                        method = "direct" if action.is_direct else "override"
                        console.print(
                            f"  [cyan]Refresh {action.package}:[/cyan] "
                            f"{file_path} already requests {action.fix_version} "
                            f"({method}); refreshing install state"
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

        # Run npm install if we changed or refreshed any package.json
        install_ok = True
        if not self.dry_run and install_targets:
            install_ok = self._run_install(install_targets)

        # Build summary
        summary_parts = []
        if applied:
            summary_parts.append(f"Upgraded {len(applied)} packages:")
            for a in applied:
                summary_parts.append(
                    f"  [{a.severity}] {a.package}: {a.current_version} -> {a.fix_version}"
                )
        if refreshed:
            summary_parts.append(
                f"\nRefreshed install state for {len(refreshed)} already-pinned packages:"
            )
            for a in refreshed:
                summary_parts.append(
                    f"  [{a.severity}] {a.package}: manifest already requests {a.fix_version}"
                )
        if skipped:
            summary_parts.append(f"\nSkipped {len(skipped)}:")
            for s in skipped:
                summary_parts.append(f"  {s}")
        if not install_ok:
            summary_parts.append("\nWARNING: npm install had errors (see above)")

        return AgentResult(
            success=len(applied) > 0 or len(refreshed) > 0,
            summary="\n".join(summary_parts),
            changes=self._changes,
            tests_passed=None,
            iterations_used=1,
        )

    def _plan_fixes(self, report: SnykReport) -> list[FixAction]:
        """Build list of fix actions from the Snyk report."""
        vulns = SnykParser.deduplicate(report.vulnerabilities)

        # Find all dependency files
        dep_files = self._find_dep_files()
        actions_by_key: dict[tuple[str, str, bool], FixAction] = {}
        grouped_vulns: dict[tuple[str, str], list] = {}

        for vuln in vulns:
            manifest_hint = self._choose_manifest_hint(vuln, dep_files) or ""
            grouped_vulns.setdefault((vuln.package_name, manifest_hint), []).append(vuln)

        for (pkg_name, manifest_hint), pkg_vulns in grouped_vulns.items():
            if not any(v.is_upgradable for v in pkg_vulns):
                continue

            fix_version = self._select_fix_version(pkg_name, pkg_vulns)
            if not fix_version:
                continue

            current = pkg_vulns[0].version
            max_sev = max(pkg_vulns, key=lambda vuln: vuln.severity.rank).severity.value.upper()
            vuln_ids = [v.id for v in pkg_vulns]

            # Validate the upgrade is safe
            safe, reason = _is_safe_upgrade(current, fix_version)
            if not safe:
                if self.verbose:
                    console.print(f"  [yellow]Skip {pkg_name}:[/yellow] {reason}")
                continue

            # Check if DIRECT dependency (in dependencies/devDependencies)
            candidate_files = [manifest_hint] if manifest_hint else dep_files
            found_in = [
                dep_file for dep_file in candidate_files
                if dep_file and self._manifest_has_direct_dependency(dep_file, pkg_name)
            ]

            if not found_in and manifest_hint and self._manifest_has_direct_dependency(
                manifest_hint, pkg_name
            ):
                found_in = [manifest_hint]

            if found_in:
                for f in found_in:
                    action = FixAction(
                        package=pkg_name,
                        current_version=current,
                        fix_version=fix_version,
                        severity=max_sev,
                        file_path=f,
                        is_direct=True,
                        vuln_ids=vuln_ids,
                    )
                    self._merge_action(actions_by_key, action)
            else:
                target_pkg = self._choose_override_manifest(pkg_vulns, dep_files, manifest_hint)
                if not target_pkg:
                    continue

                action = FixAction(
                    package=pkg_name,
                    current_version=current,
                    fix_version=fix_version,
                    severity=max_sev,
                    file_path=target_pkg,
                    is_direct=False,
                    vuln_ids=vuln_ids,
                )
                self._merge_action(actions_by_key, action)

        return list(actions_by_key.values())

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
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return None

            for section in PACKAGE_JSON_DEP_SECTIONS:
                deps = data.get(section)
                if not isinstance(deps, dict) or action.package not in deps:
                    continue

                old_spec = str(deps[action.package])
                if self._version_matches_spec(old_spec, action.fix_version):
                    return content

                deps[action.package] = f"{self._extract_version_prefix(old_spec)}{action.fix_version}"
                return json.dumps(data, indent=2) + "\n"

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
        if isinstance(overrides.get(action.package), str) and self._version_matches_spec(
            overrides[action.package], action.fix_version
        ):
            return content

        overrides[action.package] = f"^{action.fix_version}"
        data["overrides"] = overrides

        return json.dumps(data, indent=2) + "\n"

    def _run_install(self, manifest_paths: set[str]) -> bool:
        """Run package install commands for modified files."""
        success = True

        pkg_dirs: set[Path] = set()
        for file_path in manifest_paths:
            if not file_path.endswith("package.json"):
                continue
            pkg_dirs.add(self._resolve_install_dir(file_path))

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

    def _merge_action(
        self,
        actions_by_key: dict[tuple[str, str, bool], FixAction],
        action: FixAction,
    ) -> None:
        key = (action.package, action.file_path, action.is_direct)
        existing = actions_by_key.get(key)
        if existing is None:
            actions_by_key[key] = action
            return

        existing.vuln_ids = sorted(set(existing.vuln_ids + action.vuln_ids))
        if _severity_rank(action.severity) > _severity_rank(existing.severity):
            existing.severity = action.severity

        cur_fix = _parse_semver(existing.fix_version)
        new_fix = _parse_semver(action.fix_version)
        if cur_fix is None or (new_fix is not None and new_fix > cur_fix):
            existing.fix_version = action.fix_version

    def _select_fix_version(self, package_name: str, vulns: list) -> str | None:
        versions: list[str] = []
        for vuln in vulns:
            for path_entry in vuln.upgrade_path:
                if not isinstance(path_entry, str) or "@" not in path_entry:
                    continue
                dep_name, version = path_entry.rsplit("@", 1)
                if dep_name == package_name:
                    versions.append(version)

        if not versions:
            return None

        return max(versions, key=lambda version: _parse_semver(version) or (0, 0, 0))

    def _manifest_has_direct_dependency(self, dep_file: str, package_name: str) -> bool:
        try:
            content = (self.project_dir / dep_file).read_text()
        except OSError:
            return False

        if dep_file.endswith(".json"):
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return False

            for section in PACKAGE_JSON_DEP_SECTIONS:
                deps = data.get(section, {})
                if isinstance(deps, dict) and package_name in deps:
                    return True
            return False

        if dep_file.endswith(".txt"):
            pattern = re.compile(rf"^\s*{re.escape(package_name)}(?:\[.*\])?\s*(?:==|>=|~=)", re.MULTILINE)
            return bool(pattern.search(content))

        if dep_file.endswith(".xml"):
            return f"<artifactId>{package_name}</artifactId>" in content

        return False

    def _choose_manifest_hint(self, vuln, dep_files: list[str]) -> str | None:
        dep_file_set = set(dep_files)

        for candidate in self._target_file_candidates(vuln.display_target_file or ""):
            if candidate in dep_file_set:
                return candidate

        for project_name in filter(None, [vuln.source_project_name, vuln.from_path[0] if vuln.from_path else ""]):
            normalized_name = project_name.rsplit("@", 1)[0]
            for dep_file in dep_files:
                if not dep_file.endswith("package.json"):
                    continue
                try:
                    data = json.loads((self.project_dir / dep_file).read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                if data.get("name", "") == normalized_name:
                    return dep_file

        return None

    def _choose_override_manifest(
        self, vulns: list, dep_files: list[str], manifest_hint: str
    ) -> str | None:
        dep_file_set = set(dep_files)

        if manifest_hint and manifest_hint.endswith("package.json"):
            return manifest_hint

        for vuln in vulns:
            for candidate in self._target_file_candidates(vuln.display_target_file or ""):
                if candidate.endswith("package.json") and candidate in dep_file_set:
                    return candidate

        for vuln in vulns:
            project_name = vuln.source_project_name or (vuln.from_path[0] if vuln.from_path else "")
            if not project_name:
                continue
            normalized_name = project_name.rsplit("@", 1)[0]
            for dep_file in dep_files:
                if not dep_file.endswith("package.json"):
                    continue
                try:
                    data = json.loads((self.project_dir / dep_file).read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                if data.get("name", "") == normalized_name:
                    return dep_file

        package_jsons = [dep_file for dep_file in dep_files if dep_file.endswith("package.json")]
        if not package_jsons:
            return None
        return next((dep_file for dep_file in package_jsons if dep_file == "package.json"), package_jsons[0])

    def _target_file_candidates(self, raw_target_file: str) -> list[str]:
        if not raw_target_file:
            return []

        normalized = raw_target_file.lstrip("./").replace("\\", "/")
        path = Path(normalized)
        candidates: list[str] = []

        if normalized:
            candidates.append(normalized)

        if path.name in PACKAGE_LOCK_FILES:
            candidates.append(str(path.with_name("package.json")))

        parent = path.parent
        while True:
            for manifest_name in ("package.json", "requirements.txt", "pyproject.toml", "pom.xml"):
                candidate = manifest_name if str(parent) == "." else str(parent / manifest_name)
                if candidate not in candidates:
                    candidates.append(candidate)
            if str(parent) == ".":
                break
            parent = parent.parent

        return candidates

    def _action_already_present(self, content: str, action: FixAction, file_path: str) -> bool:
        if file_path.endswith(".json"):
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                return False

            if action.is_direct:
                for section in PACKAGE_JSON_DEP_SECTIONS:
                    deps = data.get(section, {})
                    if not isinstance(deps, dict) or action.package not in deps:
                        continue
                    return self._version_matches_spec(str(deps[action.package]), action.fix_version)

            overrides = data.get("overrides", {})
            if isinstance(overrides, dict) and action.package in overrides:
                value = overrides[action.package]
                if isinstance(value, str):
                    return self._version_matches_spec(value, action.fix_version)
            return False

        if file_path.endswith(".txt"):
            return f"{action.package}=={action.fix_version}" in content

        return False

    def _version_matches_spec(self, spec: str, version: str) -> bool:
        spec_semver = _parse_semver(spec)
        version_semver = _parse_semver(version)
        return spec_semver is not None and spec_semver == version_semver

    def _extract_version_prefix(self, version_spec: str) -> str:
        for prefix in (">=", "<=", "^", "~", ">", "<", "="):
            if version_spec.startswith(prefix):
                return prefix
        return ""

    def _resolve_install_dir(self, file_path: str) -> Path:
        manifest_path = (self.project_dir / file_path).resolve()
        package_dir = manifest_path.parent

        if any((package_dir / lock_file).exists() for lock_file in PACKAGE_LOCK_FILES):
            return package_dir

        workspace_root = self._find_workspace_root(package_dir)
        if workspace_root is not None:
            return workspace_root

        return package_dir

    def _find_workspace_root(self, start_dir: Path) -> Path | None:
        current = start_dir
        while True:
            package_json = current / "package.json"
            if package_json.exists():
                try:
                    data = json.loads(package_json.read_text())
                except (OSError, json.JSONDecodeError):
                    data = {}
                if "workspaces" in data:
                    return current

            if current == self.project_dir or current.parent == current:
                break
            current = current.parent

        return None
