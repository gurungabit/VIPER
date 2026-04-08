# VIPER

**Vulnerability Identification, Patching & Evaluation Robot**

AI-powered agent that automatically analyzes Snyk vulnerability reports, fixes insecure dependencies, and creates GitLab merge requests.

## Quick Start

```bash
uv sync
uv run viper scan --project-dir /path/to/project
uv run viper fix --project-dir /path/to/project
uv run viper mr --project-dir /path/to/project
```

## Configuration

Copy `viper.yaml.example` to `viper.yaml` and fill in your tokens.
