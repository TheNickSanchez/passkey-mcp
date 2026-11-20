"""Interactive CLI components for passkey.

Provides fuzzy-matching entry selection with arrow key navigation,
real-time masked secret input with character counts, and safe previews.
Falls back gracefully when not running in a TTY.
"""

import os
import select
import shutil
import sys
from collections.abc import Callable
from typing import TextIO

import questionary
from questionary import Style

from .keychain import PasskeyError, get_entry, list_entries

# Environment markers set by headless/agent CLI harnesses (even inside PTY shells).
# Deliberately excludes VSCODE_PID and CURSOR_TRACE_ID because human developers
# routinely run interactive shells inside VS Code / Cursor integrated terminals.
_HEADLESS_AGENT_ENV_VARS: tuple[str, ...] = (
    "PASSKEY_NO_INPUT",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "ANTIGRAVITY_AGENT",
    "CODEX_ENV",
    "OPENAI_CODEX",
)

_NO_INPUT_FORCED: bool = False


class InteractiveRequiredError(PasskeyError):
    """Raised when an interactive command is invoked in a non-TTY or --no-input session."""

    exit_code: int = 2
    default_error_code: str = "INTERACTIVE_REQUIRED"


def is_json_output_env() -> bool:
    """Return True when PASSKEY_OUTPUT=json is configured in the environment."""
    return os.environ.get("PASSKEY_OUTPUT", "").strip().lower() == "json"


def set_no_input(enabled: bool) -> None:
    """Enable or reset global --no-input mode for the current CLI invocation."""
    global _NO_INPUT_FORCED
    _NO_INPUT_FORCED = bool(enabled)


def is_no_input_forced() -> bool:
    """Return True if --no-input or PASSKEY_NO_INPUT is active."""
    if _NO_INPUT_FORCED:
        return True
    val = os.environ.get("PASSKEY_NO_INPUT", "").strip().lower()
    return val not in ("", "0", "false", "no")


def is_agent_subprocess() -> bool:
    """Return True when invoked inside a known AI coding agent subprocess."""
    override = os.environ.get("PASSKEY_ALLOW_INTERACTIVE", "").strip().lower()
    if override in ("1", "true", "yes"):
        return False
    for var in _HEADLESS_AGENT_ENV_VARS:
        val = os.environ.get(var, "").strip().lower()
        if val not in ("", "0", "false", "no"):
            return True
    return False


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
    - --no-input / PASSKEY_NO_INPUT is active
    - Running inside a headless AI agent subprocess
    - stdout is piped to another command
    - stdin is piped from another command
    - Running in a non-TTY environment (cron, scripts, etc.)

    Returns:
        True if running interactively, False otherwise
    """
    if is_no_input_forced() or is_agent_subprocess():
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def can_prompt_interactively() -> bool:
    """Return True only when human interactive prompting is allowed and attached to a TTY."""
    if is_no_input_forced() or is_agent_subprocess():
        return False
    return is_interactive()


def require_interactive(
    operation: str,
    *,
    human_command: str,
    alternative: str | None = None,
    entry: str | None = None,
) -> None:
    """Fail fast with exit code 2 when interactive input is unavailable or disabled."""
    if can_prompt_interactively():
        return

    if is_no_input_forced():
        reason = "--no-input is set"
    elif is_agent_subprocess():
        reason = "detected AI agent subprocess"
    else:
        reason = "stdin/stdout is not a TTY"

    lines = [
        f"'{operation}' requires an interactive terminal ({reason}).",
        f"  Ask the user to run in their terminal: {human_command}",
    ]
    if alternative:
        lines.append(f"  Headless alternative: {alternative}")
    lines.append("  Security rule: Never ask the user to paste secret values into chat.")
    raise InteractiveRequiredError(
        "\n".join(lines),
        error_code="INTERACTIVE_REQUIRED",
        entry=entry,
        remediation_command=alternative or human_command,
    )


def _sanitize_preview_fragment(text: str) -> str:
    """Replace control whitespace in preview edges so layout never breaks."""
    return text.replace("\n", "↵").replace("\r", "↵").replace("\t", "⇥")


def format_secret_preview(value: str) -> str:
    """Format a non-sensitive length + masked preview for verification.

    Examples:
        - 36-char API key -> ``(36 chars, sk-…9a2)``
        - 8-char secret   -> ``(8 chars, ab…78)``
        - 4-char PIN      -> ``(4 chars, ••••)``
        - empty string    -> ``(0 chars, empty)``
    """
    n = len(value)
    if n == 0:
        return "(0 chars, empty)"
    unit = "char" if n == 1 else "chars"
    if n < 8:
        return f"({n} {unit}, {'•' * n})"
    edge = 2 if n < 12 else 3
    prefix = _sanitize_preview_fragment(value[:edge])
    suffix = _sanitize_preview_fragment(value[-edge:])
    return f"({n} chars, {prefix}…{suffix})"


def parse_field_shorthand(raw: str) -> tuple[str, str | None]:
    """Parse a field name prompt response, supporting ``KEY=VALUE`` shorthand.

    Splits on the first ``=`` only so values containing ``=`` (such as base64
    tokens or connection URLs) remain intact. Also strips an optional leading
    ``export `` prefix on the key name when pasted from shell snippets.
    """
    if "=" in raw:
        key_part, value = raw.split("=", 1)
        key = key_part.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        return key, value
    return raw.strip(), None


def _posix_read_token(fd: int) -> str | None:
    """Read one logical keystroke or escape sequence from a raw POSIX fd.

    Returns ``None`` on true kernel EOF (``os.read`` returning ``b""``).
    """
    b = os.read(fd, 1)
    if not b:
        return None

    if b == b"\x1b":
        ready, _, _ = select.select([fd], [], [], 0.025)
        if not ready:
            return ""
        b2 = os.read(fd, 1)
        if b2 in (b"[", b"O"):
            seq = bytearray(b"\x1b" + b2)
            for _ in range(16):
                r2, _, _ = select.select([fd], [], [], 0.01)
                if not r2:
                    break
                ch = os.read(fd, 1)
                if not ch:
                    break
                seq.extend(ch)
                if 0x40 <= ch[0] <= 0x7E:
                    break
            if bytes(seq) == b"\x1b[3~":
                return "\x7f"
            return ""
        return ""

    first = b[0]
    if first < 0x80:
        return b.decode("ascii", errors="ignore")

    if (first & 0xE0) == 0xC0:
        need = 1
    elif (first & 0xF0) == 0xE0:
        need = 2
    elif (first & 0xF8) == 0xF0:
        need = 3
    else:
        need = 0

    buf = bytearray(b)
    for _ in range(need):
        ready, _, _ = select.select([fd], [], [], 0.02)
        if not ready:
            break
        nxt = os.read(fd, 1)
        if not nxt:
            break
        buf.extend(nxt)
    return bytes(buf).decode("utf-8", errors="replace")


def _windows_read_token() -> str:
    """Read one logical keystroke from Windows console via msvcrt."""
    import msvcrt  # type: ignore[import-not-found]

    ch = msvcrt.getwch()
    if ch in ("\x00", "\xe0"):
        ext = msvcrt.getwch()
        if ext == "S":  # Delete key
            return "\x7f"
        return ""
    return ch


def prompt_secret(
    label: str = "Value",
    *,
    mask_char: str = "•",
    stream: TextIO | None = None,
    _getch: Callable[[], str] | None = None,
) -> str:
    """Prompt for a secret with real-time ``•`` echo, char count, and reveal toggle.

    Features on interactive terminals:
    - Live character counter + bullet echo: ``Value for API_KEY (36 chars): •••…``
    - ``Backspace`` / ``Delete`` remove the last character
    - ``Ctrl+U`` clears the entire current input
    - ``Ctrl+R`` or ``Tab`` toggles temporary plaintext reveal (auto-remasked on Enter)
    - ``Ctrl+C`` cleanly aborts with ``KeyboardInterrupt``

    Falls back to reading a line from ``sys.stdin`` when stdin/stdout is not a TTY
    or when invoked under non-TTY test harnesses.
    """
    clean_label = label.rstrip()
    if clean_label.endswith(":"):
        clean_label = clean_label[:-1].rstrip()

    out = stream if stream is not None else sys.stdout

    # Determine whether we can use raw keystroke reading
    use_raw = _getch is not None
    posix_fd: int | None = None
    old_termios = None

    if not use_raw and sys.stdin.isatty() and out.isatty():
        if sys.platform == "win32":
            try:
                import msvcrt  # noqa: F401

                use_raw = True
            except ImportError:
                use_raw = False
        else:
            try:
                import termios

                posix_fd = sys.stdin.fileno()
                old_termios = termios.tcgetattr(posix_fd)
                use_raw = True
            except Exception:
                posix_fd = None
                old_termios = None
                use_raw = False

    if not use_raw:
        prompt_stream = out if out.isatty() else sys.stderr
        with _suppress_broken_pipe():
            prompt_stream.write(f"{clean_label}: ")
            prompt_stream.flush()
        line = sys.stdin.readline()
        if line == "":
            raise EOFError
        return line.rstrip("\r\n")

    buf: list[str] = []
    revealed = False

    def _render(*, force_masked: bool = False) -> None:
        n = len(buf)
        if n == 0:
            rendered = f"\r\x1b[2K{clean_label}: "
        else:
            unit = "char" if n == 1 else "chars"
            show_plain = revealed and not force_masked
            shown = "".join(buf) if show_plain else (mask_char * n)
            tag = " [revealed]" if show_plain else ""
            prefix = f"{clean_label} ({n} {unit}){tag}: "
            cols = shutil.get_terminal_size((80, 24)).columns
            avail = max(12, cols - len(prefix) - 2)
            if len(shown) > avail:
                shown = "…" + shown[-(avail - 1) :]
            rendered = f"\r\x1b[2K{prefix}{shown}"
        out.write(rendered)
        out.flush()

    if posix_fd is not None and old_termios is not None:
        import termios

        new_attrs = termios.tcgetattr(posix_fd)
        new_attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.ISIG | termios.IEXTEN)
        new_attrs[0] &= ~(termios.IXON | termios.ICRNL | termios.INLCR)
        new_attrs[6][termios.VMIN] = 1
        new_attrs[6][termios.VTIME] = 0
        termios.tcsetattr(posix_fd, termios.TCSADRAIN, new_attrs)

    def _has_pending_input() -> bool:
        if _getch is not None:
            return False
        if sys.platform == "win32":
            import msvcrt  # type: ignore[import-not-found]

            return bool(msvcrt.kbhit())
        if posix_fd is not None:
            ready, _, _ = select.select([posix_fd], [], [], 0)
            return bool(ready)
        return False

    try:
        _render()
        dirty = False
        drained_count = 0
        while True:
            if _getch is not None:
                token = _getch()
            elif sys.platform == "win32":
                token = _windows_read_token()
            else:
                assert posix_fd is not None
                token = _posix_read_token(posix_fd)

            if token is None:  # True pipe/fd EOF (os.read returned b"")
                if buf:
                    _render(force_masked=True)
                    out.write("\n")
                    out.flush()
                    return "".join(buf)
                out.write("\n")
                out.flush()
                raise EOFError

            if token != "":
                if token in ("\r", "\n"):
                    _render(force_masked=True)
                    out.write("\n")
                    out.flush()
                    return "".join(buf)

                if token == "\x03":  # Ctrl+C
                    _render(force_masked=True)
                    out.write("\n")
                    out.flush()
                    raise KeyboardInterrupt

                if token == "\x04":  # Ctrl+D / EOF
                    if not buf:
                        out.write("\n")
                        out.flush()
                        raise EOFError
                elif token in ("\x7f", "\x08", "\x1b[3~"):  # Backspace / Delete
                    if buf:
                        buf.pop()
                        dirty = True
                elif token == "\x15":  # Ctrl+U (clear input)
                    if buf:
                        buf.clear()
                        dirty = True
                elif token in ("\x12", "\t"):  # Ctrl+R or Tab (reveal/hide toggle)
                    revealed = not revealed
                    dirty = True
                else:
                    # Support multi-char tokens (e.g., pasted chunks from custom _getch)
                    for ch in token:
                        if ch in ("\r", "\n"):
                            _render(force_masked=True)
                            out.write("\n")
                            out.flush()
                            return "".join(buf)
                        if ord(ch) >= 32 and ch != "\x7f":
                            buf.append(ch)
                            dirty = True

            drained_count += 1
            if _has_pending_input() and drained_count < 4096:
                continue

            if dirty:
                _render()
                dirty = False
            drained_count = 0
    finally:
        if posix_fd is not None and old_termios is not None:
            import termios

            termios.tcsetattr(posix_fd, termios.TCSADRAIN, old_termios)


class _suppress_broken_pipe:
    """Ignore OSError on prompt writes when stderr/stdout is closed."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        return exc_type is not None and issubclass(exc_type, OSError)


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
