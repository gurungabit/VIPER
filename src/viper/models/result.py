"""Pydantic models for agent results."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FileChange(BaseModel):
    path: str
    diff: str = ""
    backup_path: str | None = None


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    result: str = ""
    iteration: int = 0


class AgentResult(BaseModel):
    success: bool = False
    changes: list[FileChange] = Field(default_factory=list)
    tests_passed: bool | None = None
    summary: str = ""
    iterations_used: int = 0
    tool_calls: list[ToolCall] = Field(default_factory=list)
