"""Shell tab completion for passkey.

Generates bash, zsh, and fish completion scripts that call 'passkey list'
and filter results. No argcomplete needed for the top-level entry completion.
"""

import subprocess
import sys


def _get_entries() -> list[str]:
    """Get all entry names for completion. Silent on errors."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "passkey", "list", "--names-only"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
    except Exception:
        pass
    return []


_BASH_SCRIPT = '''\
# passkey shell completion for bash
# Add to ~/.bashrc: eval "$(passkey completion --bash)"

_passkey_completions() {
    local cur prev commands entries
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="new list get edit delete info clone set-field run export import check audit mcp-serve init unwrap status doctor servers add config completion generate template share receive rotate"

    # First argument: complete subcommands or entry names
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        if [[ -z "$cur" ]]; then
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        else
            # Try matching entries first, fall back to commands
            entries=$(passkey list --names-only 2>/dev/null)
            if [[ -n "$entries" ]]; then
                COMPREPLY=( $(compgen -W "$entries $commands" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            fi
        fi
        return 0
    fi

    # Subcommand-specific completions
    case "$prev" in
        get|edit|delete|info|set-field|check)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries" -- "$cur") )
            return 0
            ;;
        run)
            # Complete entry names, then -- after
            entries=$(passkey list --names-only 2>/dev/null)
            if [[ "$cur" == "--" ]]; then
                COMPREPLY=("--")
            else
                COMPREPLY=( $(compgen -W "$entries" -- "$cur") )
            fi
            return 0
            ;;
        clone)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries" -- "$cur") )
            return 0
            ;;
        init)
            COMPREPLY=( $(compgen -W "claude gemini vscode cursor opencode windsurf cline zed" -- "$cur") )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "--bash --zsh --fish" -- "$cur") )
            return 0
            ;;
        *)
            # For positional fallback (passkey <entry>), complete entry names
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries" -- "$cur") )
            return 0
            ;;
    esac
}

complete -F _passkey_completions passkey
'''

_ZSH_SCRIPT = '''\
# passkey shell completion for zsh
# Add to ~/.zshrc: eval "$(passkey completion --zsh)"

_passkey() {
    local commands entries
    commands=(new list get edit delete info clone set-field run export import check audit mcp-serve init unwrap status doctor servers add config completion generate template share receive rotate)

    if (( CURRENT == 2 )); then
        entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
        _describe 'command' commands
        _describe 'entry' entries
    else
        case ${words[2]} in
            get|edit|delete|info|set-field|check)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                ;;
            run)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                ;;
            clone)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                ;;
            init)
                local tools=(claude gemini vscode cursor opencode windsurf cline zed)
                _describe 'tool' tools
                ;;
            completion)
                local opts=(--bash --zsh --fish)
                _describe 'option' opts
                ;;
            *)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                ;;
        esac
    fi
}

compdef _passkey passkey
'''

_FISH_SCRIPT = '''\
# passkey shell completion for fish
# Add to ~/.config/fish/completions/passkey.fish (or run: passkey completion --fish > ~/.config/fish/completions/passkey.fish)

# Helper: get entry names
function __passkey_entries
    passkey list --names-only 2>/dev/null
end

# Subcommands
complete -c passkey -n '__fish_use_subcommand' -a new -d 'Create a new entry'
complete -c passkey -n '__fish_use_subcommand' -a list -d 'List all entries'
complete -c passkey -n '__fish_use_subcommand' -a get -d 'Browse and copy fields'
complete -c passkey -n '__fish_use_subcommand' -a edit -d 'Edit an entry'
complete -c passkey -n '__fish_use_subcommand' -a delete -d 'Delete an entry'
complete -c passkey -n '__fish_use_subcommand' -a info -d 'Show entry details'
complete -c passkey -n '__fish_use_subcommand' -a clone -d 'Clone an entry'
complete -c passkey -n '__fish_use_subcommand' -a set-field -d 'Upsert a field'
complete -c passkey -n '__fish_use_subcommand' -a run -d 'Run command with secrets'
complete -c passkey -n '__fish_use_subcommand' -a export -d 'Export entries'
complete -c passkey -n '__fish_use_subcommand' -a import -d 'Import entries'
complete -c passkey -n '__fish_use_subcommand' -a check -d 'Verify entry fields'
complete -c passkey -n '__fish_use_subcommand' -a audit -d 'View audit log'
complete -c passkey -n '__fish_use_subcommand' -a init -d 'Migrate MCP config'
complete -c passkey -n '__fish_use_subcommand' -a unwrap -d 'Restore inline MCP configs'
complete -c passkey -n '__fish_use_subcommand' -a config -d 'Show or update settings'
complete -c passkey -n '__fish_use_subcommand' -a status -d 'Show security status'
complete -c passkey -n '__fish_use_subcommand' -a doctor -d 'Run diagnostics'
complete -c passkey -n '__fish_use_subcommand' -a servers -d 'List MCP servers'
complete -c passkey -n '__fish_use_subcommand' -a add -d 'Add MCP server credentials'
complete -c passkey -n '__fish_use_subcommand' -a generate -d 'Generate a random secret'
complete -c passkey -n '__fish_use_subcommand' -a template -d 'Manage credential templates'
complete -c passkey -n '__fish_use_subcommand' -a share -d 'Share an entry with someone'
complete -c passkey -n '__fish_use_subcommand' -a receive -d 'Receive a shared entry'
complete -c passkey -n '__fish_use_subcommand' -a rotate -d 'Rotate an entry value'
complete -c passkey -n '__fish_use_subcommand' -a completion -d 'Shell completion setup'

# Entry completions for subcommands that take entry names
complete -c passkey -n '__fish_seen_subcommand_from get edit delete info set-field check' -a '(__passkey_entries)' -d 'Entry'
complete -c passkey -n '__fish_seen_subcommand_from clone' -a '(__passkey_entries)' -d 'Source entry'
complete -c passkey -n '__fish_seen_subcommand_from run' -a '(__passkey_entries)' -d 'Entry'

# Positional fallback: passkey <entry>
complete -c passkey -n 'test (count (commandline -opc)) -eq 1' -a '(__passkey_entries)' -d 'Entry'

# Completion subcommand
complete -c passkey -n '__fish_seen_subcommand_from completion' -l bash -d 'Print bash completion script'
complete -c passkey -n '__fish_seen_subcommand_from completion' -l zsh -d 'Print zsh completion script'
complete -c passkey -n '__fish_seen_subcommand_from completion' -l fish -d 'Print fish completion script'

# Init tools
complete -c passkey -n '__fish_seen_subcommand_from init' -a 'claude gemini vscode cursor opencode windsurf cline zed' -d 'Tool'
'''


def print_completion(shell: str) -> None:
    """Print the completion script for the given shell."""
    scripts = {
        "bash": _BASH_SCRIPT,
        "zsh": _ZSH_SCRIPT,
        "fish": _FISH_SCRIPT,
    }
    if shell not in scripts:
        from .keychain import PasskeyError
        raise PasskeyError(
            f"Unknown shell: '{shell}'. Supported: {', '.join(sorted(scripts.keys()))}"
        )
    print(scripts[shell], end="")


def print_setup_instructions() -> None:
    """Print setup instructions for all shells."""
    print("""Shell completion for passkey

Add one of these to your shell config:

  Bash (~/.bashrc):
    eval "$(passkey completion --bash)"

  Zsh (~/.zshrc):
    eval "$(passkey completion --zsh)"

  Fish:
    passkey completion --fish > ~/.config/fish/completions/passkey.fish

Then restart your shell or run:
  source ~/.bashrc   # or ~/.zshrc

After setup, tab completion works for:
  passkey <TAB>         Show entries + subcommands
  passkey get <TAB>     Complete entry names
  passkey hugg<TAB>     Fuzzy-match entries
  passkey run <TAB>     Pick entries to load
""")
