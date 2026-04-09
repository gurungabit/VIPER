"""Tests for agent tool implementations."""

import json
from pathlib import Path

import pytest

from viper.agent.tools import ToolExecutor


class TestToolExecutor:
    @pytest.fixture
    def executor(self, tmp_path: Path) -> ToolExecutor:
        # Create a sample file
        (tmp_path / "test.txt").write_text("hello world")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "nested.json").write_text('{"key": "value"}')
        return ToolExecutor(project_dir=tmp_path)

    @pytest.fixture
    def dry_executor(self, tmp_path: Path) -> ToolExecutor:
        (tmp_path / "test.txt").write_text("hello world")
        return ToolExecutor(project_dir=tmp_path, dry_run=True)

    def test_read_file(self, executor: ToolExecutor):
        result = executor.execute("read_file", {"path": "test.txt"})
        assert result == "hello world"

    def test_read_file_not_found(self, executor: ToolExecutor):
        result = executor.execute("read_file", {"path": "nonexistent.txt"})
        assert "Error" in result

    def test_write_file(self, executor: ToolExecutor):
        result = executor.execute("write_file", {"path": "new.txt", "content": "new content"})
        assert "Successfully" in result
        assert (executor.project_dir / "new.txt").read_text() == "new content"

    def test_write_file_dry_run(self, dry_executor: ToolExecutor):
        result = dry_executor.execute("write_file", {"path": "new.txt", "content": "new content"})
        assert "DRY RUN" in result
        assert not (dry_executor.project_dir / "new.txt").exists()

    def test_edit_file(self, executor: ToolExecutor):
        result = executor.execute(
            "edit_file",
            {"path": "test.txt", "old_string": "hello", "new_string": "goodbye"},
        )
        assert "Replaced" in result
        assert (executor.project_dir / "test.txt").read_text() == "goodbye world"

    def test_edit_file_not_found_string(self, executor: ToolExecutor):
        result = executor.execute(
            "edit_file",
            {"path": "test.txt", "old_string": "nonexistent", "new_string": "x"},
        )
        assert "Error" in result

    def test_list_dir(self, executor: ToolExecutor):
        result = executor.execute("list_dir", {"path": "."})
        assert "sub" in result
        assert "test.txt" in result

    def test_search_files_glob(self, executor: ToolExecutor):
        result = executor.execute("search_files", {"pattern": "*.txt"})
        assert "test.txt" in result

    def test_search_files_glob_nested(self, executor: ToolExecutor):
        result = executor.execute("search_files", {"pattern": "*.json"})
        assert "nested.json" in result

    def test_bash_simple(self, executor: ToolExecutor):
        result = executor.execute("bash", {"command": "echo hello"})
        assert "hello" in result

    def test_bash_blocked_command(self, executor: ToolExecutor):
        result = executor.execute("bash", {"command": "sudo rm -rf /"})
        assert "blocked" in result.lower()

    def test_bash_blocks_audit_fix_shortcuts(self, executor: ToolExecutor):
        result = executor.execute("bash", {"command": "npm audit fix"})
        assert "blocked" in result.lower()

    def test_bash_blocks_plain_npm_audit(self, executor: ToolExecutor):
        result = executor.execute("bash", {"command": "npm audit"})
        assert "blocked" in result.lower()

    def test_done(self, executor: ToolExecutor):
        assert not executor.is_done
        result = executor.execute(
            "done",
            {"summary": "Fixed 2 vulns", "tests_passed": True, "changes": []},
        )
        assert executor.is_done
        assert executor.done_result["summary"] == "Fixed 2 vulns"
        assert executor.done_result["tests_passed"] is True

    def test_path_traversal_blocked(self, executor: ToolExecutor):
        result = executor.execute("read_file", {"path": "../../etc/passwd"})
        assert "Error" in result

    def test_unknown_tool(self, executor: ToolExecutor):
        result = executor.execute("nonexistent_tool", {})
        assert "Unknown tool" in result

    def test_changes_tracked(self, executor: ToolExecutor):
        executor.execute("write_file", {"path": "a.txt", "content": "a"})
        executor.execute("write_file", {"path": "b.txt", "content": "b"})
        assert len(executor.changes) == 2
