"""Environment variable injection for subprocess execution."""

import os
import subprocess
import sys

from .keychain import PasskeyError, get_entry


def run_with_secrets(entries: list[str], command: list[str]) -> int:
    """Run command with secrets and config from entries as environment variables.

    Args:
        entries: List of entry names to load
        command: Command and arguments to execute

    Returns:
        The command's exit code (the CLI layer owns sys.exit).

    Raises:
        PasskeyError: If entries cannot be loaded or the command fails to start.

    Note:
        If multiple entries contain the same field name,
        later entries override earlier ones.
    """
    # Security Warning about environment variable exposure
    warning = (
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SECURITY WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "Injecting secrets as environment variables can expose them to other processes\n"
        "on this system. Use this feature with caution, especially for long-lived\n"
        "processes. Prefer tools that accept secrets via stdin or other mechanisms.\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
    )
    print(warning, file=sys.stderr)

    env = os.environ.copy()
    loaded_count = 0

    try:
        for name in entries:
            entry = get_entry(name)
            if entry:
                all_vars = entry.get_all_env_vars()
                env.update(all_vars)
                loaded_count += 1
                secret_count = len(entry.fields)
                print(
                    f"Loaded {secret_count} secret(s) from '{name}' into environment",
                    file=sys.stderr,
                )
            else:
                print(f"Warning: Entry '{name}' not found, skipping", file=sys.stderr)
    except PasskeyError as e:
        raise PasskeyError(f"Failed to load secrets: {e}") from e

    if loaded_count == 0:
        raise PasskeyError("No entries loaded, aborting command.")

    try:
        result = subprocess.run(command, env=env)
        return result.returncode
    except FileNotFoundError:
        raise PasskeyError(f"Command not found: '{command[0]}'") from None
    except OSError as e:
        raise PasskeyError(f"Failed to execute command: {e}") from e
