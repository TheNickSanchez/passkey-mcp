"""Backward-compatibility shim. Use mcp_commands instead."""

from .mcp_commands import (
    cmd_add,
    cmd_claude_init,
    cmd_claude_status,
    cmd_doctor,
    cmd_init,
    cmd_servers,
    cmd_status,
)

__all__ = [
    "cmd_add",
    "cmd_claude_init",
    "cmd_claude_status",
    "cmd_doctor",
    "cmd_init",
    "cmd_servers",
    "cmd_status",
]
