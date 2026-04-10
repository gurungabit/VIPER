"""Models for Snyk Code (SAST) scan results in SARIF format."""

from __future__ import annotations

from pydantic import BaseModel, Field

from viper.models.vulnerability import Severity


# SARIF level → Severity mapping (SAST has no "critical")
SARIF_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.low,
}


class CodeFlowStep(BaseModel):
    """One step in a data-flow trace (e.g. user input → sink)."""

    file_path: str
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0


class CodeIssue(BaseModel):
    """A single SAST finding from Snyk Code."""

    rule_id: str  # e.g. "python/Sqli", "javascript/XSS"
    rule_name: str = ""  # e.g. "SQL Injection", from rules[] shortDescription
    message: str  # human-readable description
    severity: Severity
    file_path: str  # relative to project root
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0
    fingerprint: str = ""  # for deduplication
    code_flow: list[CodeFlowStep] = Field(default_factory=list)
    is_autofixable: bool = False
    priority_score: int = 0


class CodeReport(BaseModel):
    """Parsed result of `snyk code test --json` (SARIF format)."""

    ok: bool = True
    issues: list[CodeIssue] = Field(default_factory=list)
    tool_name: str = "SnykCode"
    tool_version: str = ""
