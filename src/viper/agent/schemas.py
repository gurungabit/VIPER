"""OpenAI-compatible tool schemas for the VIPER agent."""

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": (
                "Execute a shell command in the project directory. "
                "Use for: npm install, npm test, pip install, pytest, mvn test, "
                "git commands, snyk commands, etc."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds (default: 300)",
                        "default": 300,
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file. Use to inspect dependency files, config, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from project root",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write content to a file, overwriting existing content. "
                "Use for creating or fully replacing files."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from project root",
                    },
                    "content": {
                        "type": "string",
                        "description": "The full file content to write",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edit_file",
            "description": (
                "Find and replace a string in a file. Safer than write_file for small changes. "
                "The old_string must match exactly (including whitespace)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from project root",
                    },
                    "old_string": {
                        "type": "string",
                        "description": "The exact string to find",
                    },
                    "new_string": {
                        "type": "string",
                        "description": "The string to replace it with",
                    },
                },
                "required": ["path", "old_string", "new_string"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and directories at a given path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path from project root (default: '.')",
                        "default": ".",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for files matching a glob pattern or grep for text in files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (e.g. '**/*.json') or text to search for",
                    },
                    "path": {
                        "type": "string",
                        "description": "Directory to search in (default: '.')",
                        "default": ".",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["glob", "grep"],
                        "description": "Search mode: 'glob' for filename patterns, 'grep' for content search",
                        "default": "glob",
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_backup",
            "description": "Create a backup of a file before modifying it. Always do this before editing dependency files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file to backup",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "restore_backup",
            "description": "Restore a file from its backup. Use when tests fail after an update.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the original file (backup is at path + '.viper.bak')",
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "done",
            "description": (
                "Signal that you have completed the task. Call this when all fixes are applied "
                "and tests pass (or when you've determined no fixes can be applied)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Human-readable summary of what was done",
                    },
                    "changes": {
                        "type": "array",
                        "description": "List of files changed",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "action": {
                                    "type": "string",
                                    "enum": ["modified", "created", "restored"],
                                },
                            },
                            "required": ["path", "action"],
                        },
                    },
                    "tests_passed": {
                        "type": "boolean",
                        "description": "Whether tests passed after applying fixes",
                    },
                },
                "required": ["summary"],
            },
        },
    },
]
