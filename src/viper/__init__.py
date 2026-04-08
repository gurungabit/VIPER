"""VIPER — Vulnerability Identification, Patching & Evaluation Robot."""

__version__ = "0.1.0"


class ViperError(Exception):
    """Base exception for VIPER."""


class ViperParseError(ViperError):
    """Failed to parse Snyk report."""


class ViperScanError(ViperError):
    """Failed to run Snyk scan."""


class ViperAgentError(ViperError):
    """Agent loop failure."""


class ViperGitLabError(ViperError):
    """GitLab API failure."""
