"""Interactive CLI components for passkey.

Provides fuzzy-matching entry selection with arrow key navigation.
Falls back gracefully when not running in a TTY.
"""

import sys

import questionary
from questionary import Style

from .keychain import PasskeyError, get_entry, list_entries

# Custom style for passkey prompts
PASSKEY_STYLE = Style(
    [
        ("qmark", "fg:cyan bold"),
        ("question", "bold"),
        ("answer", "fg:cyan bold"),
        ("pointer", "fg:cyan bold"),
        ("highlighted", "fg:cyan bold"),
        ("selected", "fg:cyan"),
        ("instruction", "fg:gray"),
    ]
)


def is_interactive() -> bool:
    """Check if we're running in an interactive terminal.

    Returns False when:
    - stdout is piped to another command
    - stdin is piped from another command
    - Running in a non-TTY environment (cron, scripts, etc.)

    Returns:
        True if running interactively, False otherwise
    """
    return sys.stdin.isatty() and sys.stdout.isatty()


def fuzzy_match(query: str, choices: list[str]) -> list[str]:
    """Filter choices using fuzzy matching.

    Matches if:
    1. Query is a prefix of the choice (case-insensitive)
    2. Query characters appear in order in the choice

    Args:
        query: Search string
        choices: List of strings to filter

    Returns:
        Filtered and sorted list of matching choices
    """
    if not query:
        return choices

    query_lower = query.lower()
    matches = []

    for choice in choices:
        choice_lower = choice.lower()

        # Exact prefix match (highest priority)
        if choice_lower.startswith(query_lower):
            matches.append((0, choice))
            continue

        # Contains match
        if query_lower in choice_lower:
            matches.append((1, choice))
            continue

        # Fuzzy match - characters appear in order
        query_idx = 0
        for char in choice_lower:
            if query_idx < len(query_lower) and char == query_lower[query_idx]:
                query_idx += 1

        if query_idx == len(query_lower):
            matches.append((2, choice))

    # Sort by match quality, then alphabetically
    matches.sort(key=lambda x: (x[0], x[1]))
    return [m[1] for m in matches]


def select_entry(
    prompt: str = "Select an entry",
    filter_prefix: str | None = None,
    allow_empty: bool = False,
) -> str | None:
    """Interactive entry selector with fuzzy search.

    Shows all passkey entries and allows arrow key navigation
    with type-to-filter functionality.

    Args:
        prompt: Question to display
        filter_prefix: Optional prefix to pre-filter entries
        allow_empty: If True, allow selecting nothing (returns None)

    Returns:
        Selected entry name, or None if cancelled/empty

    Raises:
        PasskeyError: If keychain access fails
        SystemExit: If not running interactively and no entries match
    """
    try:
        entries = list_entries()
    except PasskeyError as e:
        raise PasskeyError(str(e)) from e

    if not entries:
        raise PasskeyError("No entries found. Create one with: passkey new")

    # Pre-filter if prefix provided
    if filter_prefix:
        filtered = fuzzy_match(filter_prefix, entries)
        if len(filtered) == 1:
            return filtered[0]
        elif len(filtered) == 0:
            raise PasskeyError(
                f"No entries matching '{filter_prefix}'. Available entries: {', '.join(entries)}"
            )
        entries = filtered

    if not is_interactive():
        if filter_prefix:
            raise PasskeyError(
                f"Multiple entries match '{filter_prefix}': {', '.join(entries)}. "
                "Run in a terminal for interactive selection, or specify exact name."
            )
        else:
            raise PasskeyError(f"No entry specified. Available entries: {', '.join(entries)}")

    # Build choices
    choices = entries.copy()
    if allow_empty:
        choices.append(questionary.Choice(title="(cancel)", value=None))

    # Show interactive selector
    result = questionary.select(
        prompt,
        choices=choices,
        style=PASSKEY_STYLE,
        instruction="(Use arrow keys, type to filter)",
        use_jk_keys=False,  # Don't use j/k for navigation (conflicts with typing)
    ).ask()

    if result is None and not allow_empty:
        raise PasskeyError("Cancelled.")

    return result


def select_field(
    entry_name: str,
    prompt: str = "Select a field",
    allow_empty: bool = False,
) -> str | None:
    """Interactive field selector for a specific entry.

    Args:
        entry_name: Name of the entry to select fields from
        prompt: Question to display
        allow_empty: If True, allow selecting nothing

    Returns:
        Selected field name, or None if cancelled/empty
    """
    try:
        entry = get_entry(entry_name)
    except PasskeyError as e:
        raise PasskeyError(str(e)) from e

    if entry is None:
        raise PasskeyError(f"Entry '{entry_name}' not found")

    fields = list(entry.fields.keys())

    if not fields:
        raise PasskeyError(f"Entry '{entry_name}' has no fields")

    if len(fields) == 1:
        return fields[0]

    if not is_interactive():
        raise PasskeyError(
            f"Multiple fields in '{entry_name}': {', '.join(fields)}. "
            "Run in a terminal for interactive selection."
        )

    choices = fields.copy()
    if allow_empty:
        choices.append(questionary.Choice(title="(cancel)", value=None))

    result = questionary.select(
        prompt,
        choices=choices,
        style=PASSKEY_STYLE,
        instruction="(Use arrow keys)",
    ).ask()

    if result is None and not allow_empty:
        raise PasskeyError("Cancelled.")

    return result


def select_multiple_entries(
    prompt: str = "Select entries",
    min_count: int = 1,
) -> list[str]:
    """Interactive multi-select for entries.

    Args:
        prompt: Question to display
        min_count: Minimum number of entries to select

    Returns:
        List of selected entry names
    """
    try:
        entries = list_entries()
    except PasskeyError as e:
        raise PasskeyError(str(e)) from e

    if not entries:
        raise PasskeyError("No entries found. Create one with: passkey new")

    if not is_interactive():
        raise PasskeyError(f"No entries specified. Available entries: {', '.join(entries)}")

    result = questionary.checkbox(
        prompt,
        choices=entries,
        style=PASSKEY_STYLE,
        instruction="(Space to select, Enter to confirm)",
    ).ask()

    if result is None:
        raise PasskeyError("Cancelled.")

    if len(result) < min_count:
        raise PasskeyError(f"Please select at least {min_count} entry(ies)")

    return result


def confirm(prompt: str, default: bool = False) -> bool:
    """Interactive yes/no confirmation.

    Falls back to default if not interactive.

    Args:
        prompt: Question to display
        default: Default value if not interactive

    Returns:
        True for yes, False for no
    """
    if not is_interactive():
        return default

    result = questionary.confirm(
        prompt,
        default=default,
        style=PASSKEY_STYLE,
    ).ask()

    return result if result is not None else default
