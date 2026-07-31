"""CLI entry point for passkey.

This module is a compatibility shim: the implementation lives in the ``passkey.cli``
sub-package. External imports (e.g. ``from passkey.cli import main``) are served
by this file.
"""

from .cli import (
    create_parser,
    handle_onboarding_or_help,
    handle_run_command,
    handle_template_command,
    main,
    resolve_entry,
)

__all__ = [
    "create_parser",
    "handle_onboarding_or_help",
    "handle_run_command",
    "handle_template_command",
    "main",
    "resolve_entry",
]
