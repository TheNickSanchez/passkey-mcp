"""Backward-compatibility shim. Use mcp_config instead."""

from .mcp_config import (
    ADAPTERS,
    CLAUDE_CONFIG_PATH,
    DEFAULT_CONFIG_PATHS,
    extract_secrets,
    find_passkey_command,
    get_all_config_paths,
    get_mcp_servers,
    get_original_command,
    get_server_security_status,
    is_likely_secret,
    is_passkey_wrapped,
    rewrite_server_for_passkey,
)
from .mcp_config import (
    MCPConfigError as ClaudeConfigError,
)
from .mcp_config import (
    backup_config as backup_claude_config,
)
from .mcp_config import (
    load_config as load_claude_config,
)
from .mcp_config import (
    save_config as save_claude_config,
)

# Re-export with old names for backward compat
__all__ = [
    "CLAUDE_CONFIG_PATH",
    "DEFAULT_CONFIG_PATHS",
    "ClaudeConfigError",
    "backup_claude_config",
    "extract_secrets",
    "find_passkey_command",
    "get_all_config_paths",
    "get_mcp_servers",
    "get_original_command",
    "get_server_security_status",
    "is_likely_secret",
    "is_passkey_wrapped",
    "load_claude_config",
    "rewrite_server_for_passkey",
    "save_claude_config",
]
