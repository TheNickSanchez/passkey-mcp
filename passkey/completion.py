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
    local cur prev commands entries global_flags
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="new request list find get edit delete info entry clone set-field policy run exec project inject mount hook skill export import check audit mcp mcp-serve init unwrap status doctor servers add config completion generate template share upload receive rotate lease plugin browser-fill help version"
    global_flags="--no-input --help --version"

    # First argument: complete subcommands, global flags, or entry names
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") )
        elif [[ -z "$cur" ]]; then
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
        get|edit|set-field|browser-fill)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --no-input" -- "$cur") )
            return 0
            ;;
        delete)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --yes --no-input" -- "$cur") )
            return 0
            ;;
        info|check)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --json --no-input" -- "$cur") )
            return 0
            ;;
        policy)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries allow session prompt --all --exclude-mcp --yes --json --no-input" -- "$cur") )
            return 0
            ;;
        find)
            COMPREPLY=( $(compgen -W "--from-file --json --no-input" -- "$cur") )
            return 0
            ;;
        request)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --fields --policy --hint --reason --timeout --overwrite --json --no-input" -- "$cur") )
            return 0
            ;;
        exec)
            COMPREPLY=( $(compgen -W "--quiet --dry-run --json --no-strict --no-masking --project-dir --no-input --" -- "$cur") )
            return 0
            ;;
        project)
            COMPREPLY=( $(compgen -W "init status trust --from-file --project-dir --entries --force --no-trust --revoke --json" -- "$cur") )
            return 0
            ;;
        list|status|servers)
            COMPREPLY=( $(compgen -W "--json --no-input" -- "$cur") )
            return 0
            ;;
        doctor)
            COMPREPLY=( $(compgen -W "--deep --json --no-input" -- "$cur") )
            return 0
            ;;
        audit)
            COMPREPLY=( $(compgen -W "--limit --clear --yes --summary --verify --json --no-input" -- "$cur") )
            return 0
            ;;
        rotate)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --touch-only --no-input" -- "$cur") )
            return 0
            ;;
        run)
            # Complete entry names and run flags, then -- after
            entries=$(passkey list --names-only 2>/dev/null)
            if [[ "$cur" == "--" ]]; then
                COMPREPLY=("--")
            elif [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--quiet --dry-run --json --strict --no-masking --env-file --no-input --" -- "$cur") )
            else
                COMPREPLY=( $(compgen -W "$entries" -- "$cur") )
            fi
            return 0
            ;;
        inject)
            COMPREPLY=( $(compgen -W "-i --in-file -o --out-file --stdout --force --force-git-exposed --no-input" -- "$cur") )
            return 0
            ;;
        mount)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --path --once --max-reads --timeout --force-git-exposed --quiet --no-input" -- "$cur") )
            return 0
            ;;
        hook)
            COMPREPLY=( $(compgen -W "install check --with-skill --tool --project-dir" -- "$cur") )
            return 0
            ;;
        skill)
            COMPREPLY=( $(compgen -W "install --tool --project-dir --json" -- "$cur") )
            return 0
            ;;
        clone)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries" -- "$cur") )
            return 0
            ;;
        share)
            entries=$(passkey list --names-only 2>/dev/null)
            COMPREPLY=( $(compgen -W "$entries --fields -f --output -o --shared-by --no-passphrase --prompt-passphrase --no-copy --no-input" -- "$cur") )
            return 0
            ;;
        upload|receive)
            COMPREPLY=( $(compgen -f -W "--as --mode --no-input" -- "$cur") )
            return 0
            ;;
        --mode)
            COMPREPLY=( $(compgen -W "ask skip overwrite merge auto passkey csv chrome" -- "$cur") )
            return 0
            ;;
        init)
            COMPREPLY=( $(compgen -W "claude gemini vscode cursor opencode windsurf cline zed --dry-run --yes --force --policy --tool --no-input" -- "$cur") )
            return 0
            ;;
        config)
            COMPREPLY=( $(compgen -W "require-auth mcp-write-tools mcp-browser-broker agent-session-lease-ttl default-policy --json" -- "$cur") )
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
    commands=(new request list find get edit delete info entry clone set-field policy run exec project inject mount hook skill export import check audit mcp mcp-serve init unwrap status doctor servers add config completion generate template share upload receive rotate lease plugin browser-fill help version)

    if (( CURRENT == 2 )); then
        local global_opts=(--no-input --help --version)
        entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
        _describe 'command' commands
        _describe 'option' global_opts
        _describe 'entry' entries
    else
        case ${words[2]} in
            get|edit|set-field|browser-fill)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                ;;
            delete)
                local opts=(--yes --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            info|check)
                local opts=(--json --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            policy)
                local opts=(allow session prompt --all --exclude-mcp --yes --json --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            find)
                local opts=(--from-file --json --no-input)
                _describe 'option' opts
                ;;
            request)
                local opts=(--fields --policy --hint --reason --timeout --overwrite --json --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            exec)
                local opts=(--quiet --dry-run --json --no-strict --no-masking --project-dir --no-input)
                _describe 'option' opts
                ;;
            project)
                local opts=(init status trust --from-file --project-dir --entries --force --no-trust --revoke --json)
                _describe 'option' opts
                ;;
            config)
                local opts=(require-auth mcp-write-tools mcp-browser-broker agent-session-lease-ttl default-policy --json)
                _describe 'option' opts
                ;;
            list|status|servers|doctor)
                local opts=(--json --deep --no-input)
                _describe 'option' opts
                ;;
            audit)
                local opts=(--limit --clear --yes --summary --verify --json --no-input)
                _describe 'option' opts
                ;;
            rotate)
                local opts=(--touch-only --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            run)
                local opts=(--quiet --dry-run --json --strict --no-masking --env-file --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            inject)
                local opts=(-i --in-file -o --out-file --stdout --force --force-git-exposed --no-input)
                _describe 'option' opts
                ;;
            mount)
                local opts=(--path --once --max-reads --timeout --force-git-exposed --quiet --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            hook)
                local opts=(install check --with-skill --tool --project-dir)
                _describe 'option' opts
                ;;
            skill)
                local opts=(install --tool --project-dir --json)
                _describe 'option' opts
                ;;
            clone)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                ;;
            share)
                local opts=(--fields -f --output -o --shared-by --no-passphrase --prompt-passphrase --no-copy --no-input)
                entries=(${(f)"$(passkey list --names-only 2>/dev/null)"})
                _describe 'entry' entries
                _describe 'option' opts
                ;;
            upload|receive)
                local opts=(--as --mode --no-input)
                _describe 'option' opts
                _files
                ;;
            init)
                local tools=(claude gemini vscode cursor opencode windsurf cline zed --dry-run --yes --policy --no-input)
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

# Global flags
complete -c passkey -l no-input -d 'Never prompt on stdin; fail fast with exit code 2'

# Subcommands
complete -c passkey -n '__fish_use_subcommand' -a new -d 'Create a new entry'
complete -c passkey -n '__fish_use_subcommand' -a request -d 'Capture missing secrets via native OS dialog'
complete -c passkey -n '__fish_use_subcommand' -a list -d 'List all entries'
complete -c passkey -n '__fish_use_subcommand' -a find -d 'Locate entries by env var name'
complete -c passkey -n '__fish_use_subcommand' -a get -d 'Browse and copy fields'
complete -c passkey -n '__fish_use_subcommand' -a edit -d 'Edit an entry'
complete -c passkey -n '__fish_use_subcommand' -a delete -d 'Delete an entry'
complete -c passkey -n '__fish_use_subcommand' -a info -d 'Show entry details'
complete -c passkey -n '__fish_use_subcommand' -a entry -d 'Advanced entry operations'
complete -c passkey -n '__fish_use_subcommand' -a mcp -d 'Manage MCP server integrations'
complete -c passkey -n '__fish_use_subcommand' -a clone -d 'Clone an entry'
complete -c passkey -n '__fish_use_subcommand' -a set-field -d 'Upsert a field'
complete -c passkey -n '__fish_use_subcommand' -a policy -d 'Show or set entry access policy'
complete -c passkey -n '__fish_use_subcommand' -a run -d 'Run command with secrets'
complete -c passkey -n '__fish_use_subcommand' -a exec -d 'Auto-discover project manifest and run command'
complete -c passkey -n '__fish_use_subcommand' -a project -d 'Bootstrap and trust project manifests'
complete -c passkey -n '__fish_use_subcommand' -a inject -d 'Render passkey:// template placeholders'
complete -c passkey -n '__fish_use_subcommand' -a mount -d 'Mount ephemeral FIFO .env'
complete -c passkey -n '__fish_use_subcommand' -a hook -d 'Install AI agent pre-execution hooks'
complete -c passkey -n '__fish_use_subcommand' -a skill -d 'Install AI agent SKILL.md / rules'
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
complete -c passkey -n '__fish_use_subcommand' -a share -d 'Share an entry via pk1: token or bundle'
complete -c passkey -n '__fish_use_subcommand' -a upload -d 'Import a shared pk1: token or bundle'
complete -c passkey -n '__fish_use_subcommand' -a receive -d 'Receive a shared entry (alias for upload)'
complete -c passkey -n '__fish_use_subcommand' -a rotate -d 'Rotate an entry value'
complete -c passkey -n '__fish_use_subcommand' -a lease -d 'Manage scoped entry leases'
complete -c passkey -n '__fish_use_subcommand' -a plugin -d 'Zero-config CLI secret wrappers'
complete -c passkey -n '__fish_use_subcommand' -a browser-fill -d 'Deterministic CDP browser autofill'
complete -c passkey -n '__fish_use_subcommand' -a completion -d 'Shell completion setup'
complete -c passkey -n '__fish_use_subcommand' -a help -d 'Show help for any command'
complete -c passkey -n '__fish_use_subcommand' -a version -d 'Show passkey version'

# Entry completions for subcommands that take entry names
complete -c passkey -n '__fish_seen_subcommand_from get edit delete info set-field policy check rotate browser-fill request share' -a '(__passkey_entries)' -d 'Entry'
complete -c passkey -n '__fish_seen_subcommand_from share' -s f -l fields -d 'Specific field names to share'
complete -c passkey -n '__fish_seen_subcommand_from share' -s o -l output -d 'Write encrypted .enc bundle file'
complete -c passkey -n '__fish_seen_subcommand_from share' -l shared-by -d 'Sender identifier'
complete -c passkey -n '__fish_seen_subcommand_from share' -l no-passphrase -d 'Embed random 256-bit key in pk1: token'
complete -c passkey -n '__fish_seen_subcommand_from share' -l prompt-passphrase -d 'Prompt for custom passphrase'
complete -c passkey -n '__fish_seen_subcommand_from share' -l no-copy -d 'Print pk1: token instead of copying'
complete -c passkey -n '__fish_seen_subcommand_from upload receive' -l as -d 'Save imported entry under custom name'
complete -c passkey -n '__fish_seen_subcommand_from upload receive' -l mode -a 'ask skip overwrite merge' -d 'Collision resolution mode'
complete -c passkey -n '__fish_seen_subcommand_from policy' -a 'allow session prompt' -d 'Policy'
complete -c passkey -n '__fish_seen_subcommand_from policy' -l all -d 'Apply policy across all entries'
complete -c passkey -n '__fish_seen_subcommand_from policy' -l exclude-mcp -d 'Skip MCP server entries with --all'
complete -c passkey -n '__fish_seen_subcommand_from config' -a 'require-auth mcp-write-tools mcp-browser-broker agent-session-lease-ttl default-policy' -d 'Setting'
complete -c passkey -n '__fish_seen_subcommand_from project' -a 'init status trust' -d 'Project subcommand'
complete -c passkey -n '__fish_seen_subcommand_from clone' -a '(__passkey_entries)' -d 'Source entry'
complete -c passkey -n '__fish_seen_subcommand_from run mount' -a '(__passkey_entries)' -d 'Entry'

# Common agent & scripting flags
complete -c passkey -n '__fish_seen_subcommand_from list find request info check doctor status servers audit policy config lease plugin skill run exec project' -l json -d 'Output as JSON'
complete -c passkey -n '__fish_seen_subcommand_from find project' -l from-file -d 'Read variable names from template file'
complete -c passkey -n '__fish_seen_subcommand_from request' -l reason -d 'Error or expiry reason for rotation prompt'
complete -c passkey -n '__fish_seen_subcommand_from run exec init unwrap import' -l dry-run -d 'Validate or preview without side effects'
complete -c passkey -n '__fish_seen_subcommand_from run' -l strict -d 'Fail if any requested entry is missing'
complete -c passkey -n '__fish_seen_subcommand_from delete init audit policy' -s y -l yes -d 'Skip interactive confirmation'
complete -c passkey -n '__fish_seen_subcommand_from init request' -l policy -a 'allow session prompt' -d 'Access policy'
complete -c passkey -n '__fish_seen_subcommand_from rotate' -l touch-only -d 'Update last_rotated without prompting'
complete -c passkey -n '__fish_seen_subcommand_from mount' -l timeout -d 'Max seconds to wait for FIFO reader'
complete -c passkey -n '__fish_seen_subcommand_from inject mount' -l force-git-exposed -d 'Allow non-gitignored path'
complete -c passkey -n '__fish_seen_subcommand_from hook' -l with-skill -d 'Also install agent SKILL.md / rules'
complete -c passkey -n '__fish_seen_subcommand_from skill' -a 'install' -d 'Install agent skill files'

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
