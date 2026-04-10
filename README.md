# VIPER

**Vulnerability Identification, Patching & Evaluation Robot**

AI-powered security remediation agent that scans your project for dependency vulnerabilities and source code security issues, then autonomously fixes them.

```
██╗   ██╗██╗██████╗ ███████╗██████╗
██║   ██║██║██╔══██╗██╔════╝██╔══██╗
██║   ██║██║██████╔╝█████╗  ██████╔╝
╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚████╔╝ ██║██║     ███████╗██║  ██║
  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

## What It Does

VIPER runs two phases of security remediation in a single command:

**Phase 1 — Dependency Vulnerabilities (SCA)**
- Runs `snyk test` to find vulnerable packages
- AI agent edits `package.json` with targeted version bumps and overrides
- Verifies with `npm audit` + `snyk test` before completing
- Handles transitive dependencies via npm overrides

**Phase 2 — Source Code Security (SAST)**
- Runs `snyk code test` to find SQL injection, XSS, command injection, hardcoded secrets, etc.
- AI agent reads the vulnerable code, understands the data flow, and applies minimal secure fixes
- Runs project tests/build to ensure nothing breaks
- Verifies with `snyk code test` before completing

Both phases loop until clean or max cycles reached, with retry logic on failure.

## Quick Start

```bash
# Install
uv sync

# Authenticate with Snyk
snyk auth

# Initialize config
uv run viper init

# Run full remediation (deps + code)
uv run viper auto --project-dir /path/to/project
```

## Commands

| Command | Description |
|---------|-------------|
| `viper auto` | Full orchestrated loop: scan, fix, verify, repeat (deps + code) |
| `viper scan` | Run Snyk scan and display vulnerabilities |
| `viper fix` | Apply deterministic dependency fixes (no AI) |
| `viper report` | Generate a vulnerability report (markdown/json) |
| `viper mr` | Fix vulnerabilities and create a GitLab merge request |
| `viper init` | Create a `viper.yaml` configuration file |

## `viper auto` Options

```
--project-dir, -p    Project directory to scan
--severity, -s       Minimum severity: low, medium, high, critical (default: high)
--max-cycles, -n     Max fix-verify loops (default: 10)
--config, -c         Path to viper.yaml
--code-scan          Enable Snyk Code SAST scanning (default: on)
--no-code-scan       Skip code scanning, only fix dependencies
--verbose            Show agent tool calls (default: on)
--stream-agent       Stream live agent activity (default: on)
```

## Configuration

Copy `viper.yaml.example` to `viper.yaml`:

```yaml
snyk:
  token: ${SNYK_TOKEN}       # or run `snyk auth` for OAuth
  org: ""                     # Snyk organization ID (optional)

ai:
  model: github_copilot/claude-haiku-4.5  # any LiteLLM-supported model
  temperature: 0.2
  max_tokens: 4096

agent:
  max_iterations: 40          # max tool-use turns per AI cycle
  timeout_per_tool: 300       # seconds per tool execution
  blocked_commands:            # commands the AI agent cannot run
    - "npm audit fix"
    - "npm update"
    - "sudo"

settings:
  severity_threshold: high
  dry_run: false
```

VIPER supports any model available through [LiteLLM](https://docs.litellm.ai/) — OpenAI, Anthropic, GitHub Copilot, AWS Bedrock, Azure, etc.

## How It Works

```
viper auto
  |
  |-- Phase 1: Dependency Scan (SCA)
  |     |
  |     |-- snyk test --json
  |     |-- Plan fix units (direct bumps + transitive overrides)
  |     |-- AI agent edits package.json
  |     |-- npm install (clean install cycle)
  |     |-- Verify: npm audit + snyk test
  |     |-- Retry if issues remain (up to 3 attempts per batch)
  |     |-- Loop for next batch (up to max-cycles)
  |
  |-- Phase 2: Code Scan (SAST)
  |     |
  |     |-- snyk code test --json (SARIF format)
  |     |-- Group issues by file
  |     |-- AI agent reads code, applies secure fix
  |     |-- Verify: project tests/build + snyk code test
  |     |-- Retry if issues remain
  |     |-- Loop for next batch
  |
  |-- Generate report.md
```

## Verification Enforcement

The AI agent cannot declare "done" until it has actually verified its work:

- **SCA mode**: Must run `npm audit` AND `snyk test` after changes
- **SAST mode**: Must run project tests/build AND `snyk code test` after changes
- If the agent tries to skip verification, the system blocks it and forces tool use

This prevents false "all clean" results from unverified changes.

## Report

After each run, VIPER generates a `report.md` in the project directory with:

- Every dependency change (package, old version, new version, severity, why)
- Every code fix (rule, file, line, description, why)
- Files modified
- What remains unresolved and why

## Example Output

```
Phase 1: Dependency Vulnerabilities (SCA)

  Found 38 vulnerabilities (from 658 dependencies)
  Actionable fix units: 4 at high+ severity

  CRITICAL  flatted        3.3.3  -> 3.4.2   (override)
  HIGH      next           16.1.1 -> 16.2.3  (direct)
  HIGH      fast-xml-parser 5.2.5 -> 5.5.8   (override)
  HIGH      ajv            6.12.6 -> 6.14.0  (override)

Phase 2: Code Security (SAST)

  Found 1 code issue at high+ severity

  HIGH  Command Injection  app/api/user/search/route.ts:35

Summary
  Dep vulns fixed          38
  Code issues fixed        1
  Files modified           3
  Duration                 2m 2s
```

## Requirements

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) package manager
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) (`npm install -g snyk`)
- Node.js 18+ (for npm projects)
- A LiteLLM-compatible AI model API key

## Project Structure

```
src/viper/
  cli.py                    # Typer CLI (scan, fix, auto, mr, report, init)
  orchestrator.py           # Remediation loop (SCA + SAST phases)
  config.py                 # YAML + env var configuration
  fixer.py                  # Deterministic fix planner (FixAction)
  report_generator.py       # Markdown/JSON report generation
  agent/
    loop.py                 # AI agent LLM tool-use loop
    prompts.py              # System prompts (SCA + SAST)
    tools.py                # Sandboxed tool executor (bash, read, edit, etc.)
    schemas.py              # OpenAI-compatible tool schemas
  models/
    vulnerability.py        # Severity, Vulnerability, SnykReport
    code_issue.py           # CodeIssue, CodeReport (SARIF)
    result.py               # AgentResult, FileChange
  parsers/
    snyk_parser.py          # snyk test JSON parser
    snyk_code_parser.py     # snyk code test SARIF parser
```

## License

MIT
