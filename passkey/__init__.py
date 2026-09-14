"""Passkey - cross-platform system keychain secrets manager with MCP integration."""

from importlib.metadata import version as _package_version

from .keychain import delete_entry, get_entry, list_entries, save_entry
from .models import Entry

__version__ = _package_version("passkey-mcp")

__all__ = [
    "Entry",
    "__version__",
    "delete_entry",
    "get_entry",
    "list_entries",
    "save_entry",
]
