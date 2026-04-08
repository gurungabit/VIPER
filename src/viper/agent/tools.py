"""Tool implementations for the VIPER agent harness."""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()


IGNORED_DIRS = {
    # JS/Node
    "node_modules",
    ".npm",
    "bower_components",
    # Python
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    # Java/JVM
    "target",
    ".gradle",
    ".m2",
    # Build/Dist
    "build",
    "dist",
    "out",
    ".next",
    ".nuxt",
    # Infrastructure
    ".terraform",
    ".terragrunt-cache",
    # VCS/IDE
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    # OS
    ".DS_Store",
    # Containers
    ".docker",
    # Coverage/Reports
    "htmlcov",
    "coverage",
    ".nyc_output",
}


class ToolExecutor:
    """Executes tools called by the agent LLM."""

    def __init__(
        self,
        project_dir: Path,
        dry_run: bool = False,
        blocked_commands: list[str] | None = None,
        timeout: int = 300,
        verbose: bool = False,
    ):
        self.project_dir = project_dir.resolve()
        self.dry_run = dry_run
        self.blocked_commands = blocked_commands or [
            "rm -rf /", "sudo", "chmod", "mkfs", "dd if="
        ]
        self.timeout = timeout
        self.verbose = verbose
        self._backups: dict[str, str] = {}  # original_path -> backup_path
        self._changes: list[dict] = []
        self._done = False
        self._done_result: dict | None = None

    @property
    def is_done(self) -> bool:
        return self._done

    @property
    def done_result(self) -> dict | None:
        return self._done_result

    @property
    def changes(self) -> list[dict]:
        return self._changes

    def execute(self, tool_name: str, arguments: dict) -> str:
        """Dispatch a tool call and return the result as a string."""
        handler = getattr(self, f"_tool_{tool_name}", None)
        if handler is None:
            return f"Error: Unknown tool '{tool_name}'"

        try:
            result = handler(**arguments)
            if self.verbose:
                preview = result[:500] + "..." if len(result) > 500 else result
                console.print(f"  [dim]-> {preview}[/dim]")
            return result
        except Exception as e:
            return f"Error: {e}"

    def _resolve_path(self, path: str) -> Path:
        """Resolve a relative path within the project directory (sandboxed)."""
        resolved = (self.project_dir / path).resolve()
        if not str(resolved).startswith(str(self.project_dir)):
            raise PermissionError(f"Path '{path}' escapes project directory")
        return resolved

    def _is_ignored(self, path: Path) -> bool:
        """Check if a path is inside an ignored directory."""
        try:
            rel = path.resolve().relative_to(self.project_dir)
        except ValueError:
            return False
        return any(part in IGNORED_DIRS for part in rel.parts)

    # --- Tool implementations ---

    def _tool_bash(self, command: str, timeout: int | None = None) -> str:
        """Execute a shell command."""
        for blocked in self.blocked_commands:
            if blocked in command:
                return f"Error: Command blocked for safety (contains '{blocked}')"

        effective_timeout = timeout or self.timeout

        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.project_dir,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}" if output else result.stderr
            if not output:
                output = f"(exit code: {result.returncode})"
            else:
                output += f"\n(exit code: {result.returncode})"

            # Truncate very long output
            if len(output) > 10000:
                output = output[:5000] + "\n\n... (truncated) ...\n\n" + output[-3000:]

            return output
        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after {effective_timeout} seconds"
        except Exception as e:
            return f"Error executing command: {e}"

    def _tool_read_file(self, path: str) -> str:
        """Read file contents."""
        resolved = self._resolve_path(path)
        if self._is_ignored(resolved):
            return f"Error: Path is in an ignored directory (node_modules, .venv, etc.): {path}"
        if not resolved.exists():
            return f"Error: File not found: {path}"
        if not resolved.is_file():
            return f"Error: Not a file: {path}"

        content = resolved.read_text(errors="replace")
        if len(content) > 50000:
            content = content[:25000] + "\n\n... (truncated) ...\n\n" + content[-15000:]
        return content

    def _tool_write_file(self, path: str, content: str) -> str:
        """Write content to a file."""
        resolved = self._resolve_path(path)
        if self._is_ignored(resolved):
            return f"Error: Cannot write to ignored directory (node_modules, .venv, etc.): {path}"
        if self.dry_run:
            return f"[DRY RUN] Would write {len(content)} chars to {path}"
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content)
        self._changes.append({"path": path, "action": "modified"})
        return f"Successfully wrote {len(content)} chars to {path}"

    def _tool_edit_file(self, path: str, old_string: str, new_string: str) -> str:
        """Find and replace in a file."""
        resolved = self._resolve_path(path)
        if self._is_ignored(resolved):
            return f"Error: Cannot edit files in ignored directory (node_modules, .venv, etc.): {path}"
        if not resolved.exists():
            return f"Error: File not found: {path}"

        content = resolved.read_text()
        if old_string not in content:
            return f"Error: old_string not found in {path}"

        count = content.count(old_string)

        if self.dry_run:
            return f"[DRY RUN] Would replace {count} occurrence(s) in {path}"

        new_content = content.replace(old_string, new_string)
        resolved.write_text(new_content)
        self._changes.append({"path": path, "action": "modified"})
        return f"Replaced {count} occurrence(s) in {path}"

    def _tool_list_dir(self, path: str = ".") -> str:
        """List directory contents."""
        resolved = self._resolve_path(path)
        if not resolved.exists():
            return f"Error: Directory not found: {path}"
        if not resolved.is_dir():
            return f"Error: Not a directory: {path}"

        entries = sorted(resolved.iterdir(), key=lambda p: (not p.is_dir(), p.name))
        lines = []
        skipped = 0
        for entry in entries:
            if entry.name in IGNORED_DIRS:
                skipped += 1
                continue
            if len(lines) >= 200:
                break
            rel = entry.relative_to(self.project_dir)
            prefix = "[DIR]  " if entry.is_dir() else "[FILE] "
            lines.append(f"{prefix}{rel}")

        if len(entries) - skipped > 200:
            lines.append(f"... and {len(entries) - skipped - 200} more entries")
        if skipped:
            lines.append(f"({skipped} ignored directories hidden: node_modules, .venv, etc.)")

        return "\n".join(lines) if lines else "(empty directory)"

    def _tool_search_files(
        self, pattern: str, path: str = ".", mode: str = "glob"
    ) -> str:
        """Search for files by glob or grep."""
        resolved = self._resolve_path(path)

        if mode == "grep":
            try:
                result = subprocess.run(
                    ["grep", "-r", "-l", "--include=*", "-m", "20", pattern, str(resolved)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.stdout:
                    # Make paths relative
                    lines = []
                    for line in result.stdout.strip().split("\n"):
                        try:
                            rel = Path(line).relative_to(self.project_dir)
                            lines.append(str(rel))
                        except ValueError:
                            lines.append(line)
                    return "\n".join(lines[:50])
                return "No matches found"
            except Exception as e:
                return f"Error: {e}"

        # Glob mode
        matches = []
        for root, dirs, files in os.walk(resolved):
            # Skip common non-project dirs
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
            for name in files:
                if fnmatch.fnmatch(name, pattern):
                    rel = Path(root, name).relative_to(self.project_dir)
                    matches.append(str(rel))
                    if len(matches) >= 50:
                        break
            if len(matches) >= 50:
                break

        return "\n".join(matches) if matches else "No matches found"

    def _tool_create_backup(self, path: str) -> str:
        """Create a backup of a file."""
        resolved = self._resolve_path(path)
        if not resolved.exists():
            return f"Error: File not found: {path}"

        backup_path = resolved.with_suffix(resolved.suffix + ".viper.bak")
        shutil.copy2(resolved, backup_path)
        self._backups[str(resolved)] = str(backup_path)
        return f"Backup created: {path} -> {backup_path.name}"

    def _tool_restore_backup(self, path: str) -> str:
        """Restore a file from backup."""
        resolved = self._resolve_path(path)
        backup_path = resolved.with_suffix(resolved.suffix + ".viper.bak")

        if not backup_path.exists():
            return f"Error: No backup found for {path}"

        shutil.copy2(backup_path, resolved)
        self._changes = [c for c in self._changes if c["path"] != path]
        self._changes.append({"path": path, "action": "restored"})
        return f"Restored {path} from backup"

    def _tool_done(
        self,
        summary: str,
        changes: list[dict] | None = None,
        tests_passed: bool | None = None,
    ) -> str:
        """Signal task completion."""
        self._done = True
        self._done_result = {
            "summary": summary,
            "changes": changes or self._changes,
            "tests_passed": tests_passed,
        }
        return "Task marked as complete."

    def cleanup_backups(self) -> None:
        """Remove all backup files created during this session."""
        for backup_path in self._backups.values():
            try:
                Path(backup_path).unlink(missing_ok=True)
            except OSError:
                pass
