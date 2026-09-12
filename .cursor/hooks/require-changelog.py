#!/usr/bin/env python3
"""Deny git push / gh pr create when this branch has no CHANGELOG.md vs main."""

from __future__ import annotations

import json
import subprocess
import sys

ALLOW = json.dumps({"permission": "allow"})
COMMANDS_THAT_PUBLISH = ("git push", "gh pr create", "gh pr edit")


def git_lines(args: list[str]) -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", *args],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def changed_vs_main() -> set[str]:
    names: set[str] = set()
    for args in (
        ["diff", "--name-only", "main...HEAD"],
        ["diff", "--name-only", "main"],
        ["diff", "--name-only", "--cached"],
        ["diff", "--name-only"],
    ):
        names.update(git_lines(args))
    return names


def is_publish_command(command: str) -> bool:
    lowered = command.strip().lower()
    return any(token in lowered for token in COMMANDS_THAT_PUBLISH)


def deny(message: str) -> None:
    print(
        json.dumps(
            {
                "permission": "deny",
                "user_message": message,
                "agent_message": message,
            }
        )
    )


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        print(ALLOW)
        return

    command = str(payload.get("command") or "")
    if not is_publish_command(command):
        print(ALLOW)
        return

    changed = changed_vs_main()
    if not changed:
        print(ALLOW)
        return

    if "CHANGELOG.md" not in changed:
        deny(
            "This branch differs from main but CHANGELOG.md was not updated. "
            "Run the sys-release agent: add an [Unreleased] bullet and bump "
            "patch/minor/major in pyproject.toml and passkey/__init__.py, then retry."
        )
        return

    print(ALLOW)


if __name__ == "__main__":
    main()
