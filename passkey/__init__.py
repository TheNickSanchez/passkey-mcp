"""Passkey - cross-platform system keychain secrets manager with MCP integration."""

__version__ = "1.1.0"

from .keychain import delete_entry, get_entry, list_entries, save_entry
from .models import Entry

__all__ = [
    "Entry",
    "__version__",
    "delete_entry",
    "get_entry",
    "list_entries",
    "save_entry",
]
