"""VIPER configuration via Pydantic Settings."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class SnykConfig(BaseModel):
    token: str = ""
    org: str = ""


class GitLabConfig(BaseModel):
    url: str = "https://gitlab.com"
    token: str = ""
    project_id: str = ""
    target_branch: str = "main"


class AIConfig(BaseModel):
    model: str = "github_copilot/claude-sonnet-4-6"
    temperature: float = 0.2
    max_tokens: int = 4096


class AgentConfig(BaseModel):
    max_iterations: int = 30
    timeout_per_tool: int = 300
    blocked_commands: list[str] = Field(
        default_factory=lambda: ["rm -rf /", "sudo", "chmod", "mkfs", "dd if="]
    )


class ViperConfig(BaseSettings):
    snyk: SnykConfig = Field(default_factory=SnykConfig)
    gitlab: GitLabConfig = Field(default_factory=GitLabConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    severity_threshold: str = "medium"
    dry_run: bool = False

    model_config = {"env_prefix": "VIPER_", "env_nested_delimiter": "__"}

    @classmethod
    def load(cls, config_path: Path | None = None) -> ViperConfig:
        """Load config from YAML file with env var interpolation, then overlay env vars."""
        data: dict[str, Any] = {}
        if config_path and config_path.exists():
            raw = config_path.read_text()
            raw = _interpolate_env_vars(raw)
            data = yaml.safe_load(raw) or {}
            if "settings" in data:
                settings = data.pop("settings")
                data.update(settings)
        return cls(**data)


def _interpolate_env_vars(text: str) -> str:
    """Replace ${ENV_VAR} and ${ENV_VAR:-default} patterns with env values."""

    def _replace(match: re.Match) -> str:
        var = match.group(1)
        if ":-" in var:
            name, default = var.split(":-", 1)
            return os.environ.get(name, default)
        return os.environ.get(var, "")

    return re.sub(r"\$\{([^}]+)}", _replace, text)
