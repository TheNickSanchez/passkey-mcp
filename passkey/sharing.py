"""Team sharing UX layer over inline encrypted pk1: tokens and PK01 bundles."""

import base64
import getpass
import json
import os
import re
import secrets
import struct
import sys
import zlib
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .audit import log_operation
from .bundle import (
    FORMAT_VERSION,
    KEY_LEN,
    MAGIC,
    MIN_PASSPHRASE_LEN,
    NONCE_LEN,
    SALT_LEN,
    _derive_key,
    check_file_permissions,
    import_bundle,
)
from .clipboard import copy_with_autoclear
from .commands import _validate_entry_name
from .keychain import PasskeyError, get_entry, list_entries, save_entry
from .models import VALID_POLICIES, Entry, is_valid_name

TOKEN_PREFIX = "pk1:"
TOKEN_VERSION = 1
FLAG_ZLIB = 0x01
FLAG_EMBEDDED_KEY = 0x02
MAX_TOKEN_PAYLOAD_BYTES = 262_144

_TOKEN_HEADER_LEN = 2 + SALT_LEN + NONCE_LEN  # 46 bytes
_GCM_TAG_LEN = 16
_ORIG_IMPORT_BUNDLE = import_bundle

# 256 curated words for passphrase generation (~64 bits of entropy with 8 words)
_PASSPHRASE_WORDS = [
    "alpine", "anchor", "autumn", "bamboo", "basket", "beacon", "bison", "blaze",
    "breeze", "bridge", "bronze", "canyon", "cedar", "charm", "cipher", "cobalt",
    "cotton", "crystal", "current", "dance", "delta", "desert", "dragon", "dream",
    "eagle", "ember", "emerald", "falcon", "feather", "fjord", "flame", "flint",
    "forest", "frost", "garden", "glacier", "golden", "granite", "harbor", "hazel",
    "hermit", "hiro", "horizon", "hydra", "indigo", "ivory", "jade", "jungle",
    "karma", "kepler", "knight", "lagoon", "lantern", "lemon", "lotus", "lunar",
    "magnet", "marble", "meadow", "mirage", "mocha", "monsoon", "nectar", "nimble",
    "north", "novel", "oasis", "olive", "onward", "osprey", "ocean", "otter",
    "panda", "parrot", "pascal", "peach", "pearl", "pepper", "phoenix", "plasma",
    "plume", "polar", "prism", "puzzle", "quartz", "raven", "ripple", "river",
    "saddle", "saffron", "salmon", "sandal", "scarlet", "shadow", "shield", "silica",
    "silver", "solar", "sonic", "spice", "spirit", "spring", "spruce", "stone",
    "storm", "summit", "sunset", "supply", "surge", "swamp", "swift", "tempest",
    "thatch", "timber", "titan", "torch", "trail", "transit", "triple", "tundra",
    "tunnel", "turtle", "valley", "velvet", "venus", "viper", "vista", "vivid",
    "voyage", "walrus", "wander", "warmth", "willow", "winter", "wisdom", "wrench",
    "zenith", "zephyr", "zinc", "atlas", "aurora", "azure", "basalt", "binary",
    "bloom", "bold", "brass", "cider", "cliff", "cloud", "coral", "crux",
    "dawn", "dune", "echo", "fern", "fox", "gale", "gaze", "glow",
    "grain", "helm", "hemp", "hull", "iris", "iron", "kite", "lava",
    "lime", "lynx", "mica", "mist", "moss", "neon", "node", "opal",
    "peak", "pine", "pond", "puma", "rail", "reed", "rock", "rose",
    "ruby", "gem", "seal", "silk", "snow", "sol", "spur", "star",
    "stem", "tide", "tiger", "tone", "tree", "vale", "vine", "wave",
    "wolf", "wood", "yarn", "yoga", "yoke", "hex", "bolt", "cask",
    "dell", "fawn", "glen", "haze", "isle", "jazz", "kelp", "lily",
    "mink", "nape", "nova", "orca", "plum", "quay", "raft", "rune",
    "ivy", "tarn", "urn", "wane", "wisp", "yell", "zest", "amber",
    "brick", "cherry", "clove", "daisy", "elder", "flora", "forge", "jab",
    "maple", "honey", "mango", "cocoa", "berry", "aspen", "lilac", "magnolia",
    "fable", "grove", "haven", "jewel", "lance", "mirth", "opera", "pixel",
    "quest", "kit", "piano", "vapor", "glint", "hoist", "joust", "knack",
]
_PASSPHRASE_WORD_SET = frozenset(_PASSPHRASE_WORDS)


def generate_passphrase(num_words: int = 8) -> str:
    """Generate a random passphrase from the wordlist.

    Args:
        num_words: Number of words (default 8 = ~64 bits of entropy)

    Returns:
        Passphrase string with words joined by hyphens
    """
    words = [secrets.choice(_PASSPHRASE_WORDS) for _ in range(num_words)]
    return "-".join(words)


def normalize_passphrase(raw: str) -> str:
    """Normalize multi-word wordlist passphrases pasted with spaces, newlines, or mixed case."""
    stripped = raw.strip()
    if not stripped:
        return raw
    parts = [p for p in re.split(r"[\s-]+", stripped.lower()) if p]
    if len(parts) >= 2 and all(p in _PASSPHRASE_WORD_SET for p in parts):
        return "-".join(parts)
    return raw


def _prompt_share_passphrase(label: str = "Passphrase") -> str:
    """Prompt for a passphrase with masked bullet feedback on TTY or getpass fallback."""
    from .interactive import is_interactive, prompt_secret

    if is_interactive():
        return prompt_secret(label)
    clean = label.rstrip().rstrip(":")
    return getpass.getpass(f"{clean}: ")


def guard_no_token_in_argv(file_arg: str | None) -> None:
    """Refuse inline pk1: tokens passed via CLI argv (Landmine #2)."""
    if not file_arg:
        return
    compact = re.sub(r"\s+", "", file_arg.strip()).strip("'\"`")
    if compact.lower().startswith(TOKEN_PREFIX):
        raise PasskeyError(
            "Refusing 'pk1:' share token in CLI arguments "
            "(process argv and shell history are visible to other local tools).\n"
            "  Run bare 'passkey upload' and paste the token at the masked prompt instead.",
            error_code="INVALID_USAGE",
            remediation_command="passkey upload",
        )


def encode_share_token(
    entry: Entry,
    *,
    passphrase: str | None,
    shared_by: str | None = None,
) -> str:
    """Encode an Entry into a compact AAD-authenticated URL-safe pk1:... token."""
    if not entry.fields:
        raise PasskeyError(f"Entry '{entry.name}' has no secret fields to share")

    clean_config = {
        k: v for k, v in entry.config.items() if k not in ("_shared_by", "_shared_at")
    }
    payload_obj: dict[str, object] = {
        "v": 1,
        "n": entry.name,
        "f": dict(entry.fields),
    }
    if clean_config:
        payload_obj["c"] = clean_config
    if entry.policy and entry.policy != "allow":
        payload_obj["p"] = entry.policy
    if shared_by:
        payload_obj["by"] = shared_by
    payload_obj["at"] = datetime.now().isoformat(timespec="seconds")

    raw_json = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
    if len(raw_json) > MAX_TOKEN_PAYLOAD_BYTES:
        raise PasskeyError(
            f"Entry payload exceeds maximum share token size ({MAX_TOKEN_PAYLOAD_BYTES} bytes)"
        )

    if passphrase is None:
        flags = FLAG_ZLIB | FLAG_EMBEDDED_KEY
        key_or_salt = os.urandom(KEY_LEN)
        key = key_or_salt
    else:
        if len(passphrase) < MIN_PASSPHRASE_LEN:
            raise PasskeyError(
                f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )
        flags = FLAG_ZLIB
        key_or_salt = os.urandom(SALT_LEN)
        key = _derive_key(passphrase, key_or_salt)

    nonce = os.urandom(NONCE_LEN)
    compressed = zlib.compress(raw_json, level=9)
    header = bytes([TOKEN_VERSION, flags]) + key_or_salt + nonce
    ct = AESGCM(key).encrypt(nonce, compressed, b"pk1:" + header)

    encoded = base64.urlsafe_b64encode(header + ct).rstrip(b"=").decode("ascii")
    return f"{TOKEN_PREFIX}{encoded}"


def decode_share_token(
    token_str: str,
    *,
    passphrase_fn: Callable[[], str] | None = None,
) -> tuple[Entry, dict]:
    """Verify, decrypt, and parse a pk1:... inline share token."""
    cleaned = re.sub(r"\s+", "", token_str.strip()).strip("'\"`")
    if not cleaned.startswith(TOKEN_PREFIX):
        raise PasskeyError(
            "Invalid share token: expected 'pk1:' prefix",
            error_code="INVALID_TOKEN",
        )

    b64 = cleaned[len(TOKEN_PREFIX) :].rstrip("=")
    if not b64 or not re.fullmatch(r"[A-Za-z0-9_-]+", b64):
        raise PasskeyError(
            "Invalid share token: malformed base64 encoding",
            error_code="INVALID_TOKEN",
        )

    padded = b64 + ("=" * ((-len(b64)) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise PasskeyError(
            "Invalid share token: malformed base64 encoding",
            error_code="INVALID_TOKEN",
        ) from e

    if len(raw) < _TOKEN_HEADER_LEN + _GCM_TAG_LEN:
        raise PasskeyError(
            "Invalid share token: truncated frame",
            error_code="INVALID_TOKEN",
        )

    version = raw[0]
    if version != TOKEN_VERSION:
        raise PasskeyError(
            f"Unsupported share token version: {version}",
            error_code="UNSUPPORTED_VERSION",
        )

    flags = raw[1]
    if flags & ~0x03 != 0:
        raise PasskeyError(
            f"Unsupported share token flags: 0x{flags:02x}",
            error_code="UNSUPPORTED_FLAGS",
        )

    header = raw[:_TOKEN_HEADER_LEN]
    key_or_salt = raw[2 : 2 + SALT_LEN]
    nonce = raw[2 + SALT_LEN : _TOKEN_HEADER_LEN]
    ct = raw[_TOKEN_HEADER_LEN:]
    aad = b"pk1:" + header

    if flags & FLAG_EMBEDDED_KEY:
        try:
            pt_raw = AESGCM(key_or_salt).decrypt(nonce, ct, aad)
        except Exception:
            raise PasskeyError(
                "Decryption failed: corrupted or tampered share token"
            ) from None
    else:
        effective_fn = passphrase_fn or (lambda: _prompt_share_passphrase("Passphrase"))
        raw_phrase = effective_fn()
        norm_phrase = normalize_passphrase(raw_phrase)
        key = _derive_key(norm_phrase, key_or_salt)
        try:
            pt_raw = AESGCM(key).decrypt(nonce, ct, aad)
        except Exception:
            if norm_phrase != raw_phrase:
                try:
                    alt_key = _derive_key(raw_phrase, key_or_salt)
                    pt_raw = AESGCM(alt_key).decrypt(nonce, ct, aad)
                except Exception:
                    raise PasskeyError(
                        "Decryption failed: wrong passphrase or corrupted token"
                    ) from None
            else:
                raise PasskeyError(
                    "Decryption failed: wrong passphrase or corrupted token"
                ) from None

    if flags & FLAG_ZLIB:
        try:
            decomp = zlib.decompressobj()
            pt = decomp.decompress(pt_raw, MAX_TOKEN_PAYLOAD_BYTES + 1)
        except zlib.error as e:
            raise PasskeyError("Invalid share token: corrupted compressed payload") from e
        if len(pt) > MAX_TOKEN_PAYLOAD_BYTES or decomp.unconsumed_tail:
            raise PasskeyError(
                f"Share token payload exceeds maximum size ({MAX_TOKEN_PAYLOAD_BYTES} bytes)"
            )
        try:
            tail = decomp.flush(MAX_TOKEN_PAYLOAD_BYTES + 1 - len(pt))
        except zlib.error as e:
            raise PasskeyError("Invalid share token: corrupted compressed payload") from e
        pt = pt + tail
        if len(pt) > MAX_TOKEN_PAYLOAD_BYTES or not decomp.eof:
            raise PasskeyError(
                f"Share token payload exceeds maximum size ({MAX_TOKEN_PAYLOAD_BYTES} bytes)"
            )
    else:
        if len(pt_raw) > MAX_TOKEN_PAYLOAD_BYTES:
            raise PasskeyError(
                f"Share token payload exceeds maximum size ({MAX_TOKEN_PAYLOAD_BYTES} bytes)"
            )
        pt = pt_raw

    try:
        payload = json.loads(pt.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise PasskeyError(f"Invalid share token payload: {e}") from e

    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise PasskeyError("Invalid share token payload schema")

    name = payload.get("n")
    if not is_valid_name(name):
        raise PasskeyError(f"Invalid entry name in share token: {name!r}")

    raw_fields = payload.get("f")
    if (
        not isinstance(raw_fields, dict)
        or not raw_fields
        or not all(
            isinstance(k, str) and bool(k.strip()) and isinstance(v, str)
            for k, v in raw_fields.items()
        )
    ):
        raise PasskeyError("Share token contains invalid or empty secret fields")

    raw_config = payload.get("c") or {}
    if not isinstance(raw_config, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw_config.items()
    ):
        raise PasskeyError("Share token contains invalid config metadata")

    raw_policy = payload.get("p", "allow")
    if raw_policy not in VALID_POLICIES:
        raise PasskeyError(f"Invalid policy in share token: {raw_policy!r}")

    assert isinstance(name, str)
    entry = Entry(
        name=name,
        fields=dict(raw_fields),
        config={k: v for k, v in raw_config.items() if k not in ("_shared_by", "_shared_at")},
        source="share-token",
        policy=raw_policy,
    )
    meta = {
        "shared_by": payload.get("by") or None,
        "shared_at": payload.get("at") or None,
        "embedded_key": bool(flags & FLAG_EMBEDDED_KEY),
    }
    return entry, meta


def _normalize_field_filter(raw_fields: list[str] | None) -> list[str]:
    """Split comma/space-separated field filters while preserving order."""
    if not raw_fields:
        return []
    merged: list[str] = []
    for item in raw_fields:
        for part in item.split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in merged:
                merged.append(cleaned)
    return merged


def cmd_share(
    entry_name: str,
    output_path: str | None = None,
    shared_by: str | None = None,
    *,
    fields: list[str] | None = None,
    no_passphrase: bool = False,
    prompt_passphrase: bool = False,
    no_copy: bool = False,
) -> str | Path | None:
    """Share an entry via an inline pk1: token (default) or encrypted PK01 .enc bundle."""
    from .interactive import PASSKEY_STYLE, is_interactive

    if no_passphrase and prompt_passphrase:
        raise PasskeyError(
            "'--no-passphrase' and '--prompt-passphrase' cannot be used together",
            error_code="INVALID_USAGE",
        )
    if no_passphrase and output_path:
        raise PasskeyError(
            "'--no-passphrase' cannot be combined with '--output' "
            "(.enc bundle files always require a passphrase).",
            error_code="INVALID_USAGE",
        )

    entry = get_entry(entry_name)
    if not entry:
        raise PasskeyError(
            f"Entry '{entry_name}' not found",
            error_code="ENTRY_NOT_FOUND",
            entry=entry_name,
        )

    requested_fields = _normalize_field_filter(fields)
    clean_entry_config = {
        k: v for k, v in entry.config.items() if k not in ("_shared_by", "_shared_at")
    }

    if requested_fields:
        selected_secrets: dict[str, str] = {}
        selected_config: dict[str, str] = {}
        all_entry_names: set[str] | None = None
        for fname in requested_fields:
            if fname in entry.fields:
                selected_secrets[fname] = entry.fields[fname]
            elif fname in clean_entry_config:
                selected_config[fname] = clean_entry_config[fname]
            else:
                if all_entry_names is None:
                    all_entry_names = set(list_entries())
                if fname in all_entry_names and fname != entry.name:
                    raise PasskeyError(
                        f"'{fname}' is not a field on entry '{entry.name}' — "
                        "it matches another keychain entry.\n"
                        f"  Positional arguments after '{entry.name}' filter fields on that entry.\n"
                        "  To export multiple entries into one encrypted bundle, run:\n"
                        f"    passkey export shared.enc --encrypt --entries {entry.name} {fname}",
                        error_code="INVALID_USAGE",
                    )
                avail = sorted([*entry.fields.keys(), *clean_entry_config.keys()])
                avail_str = ", ".join(avail) if avail else "(none)"
                raise PasskeyError(
                    f"Field '{fname}' not found on entry '{entry.name}'. "
                    f"Available fields: {avail_str}",
                    error_code="FIELD_NOT_FOUND",
                    entry=entry.name,
                )
        if not selected_secrets:
            raise PasskeyError(
                f"Entry '{entry.name}' requires at least one secret field to share"
            )
    else:
        if not entry.fields:
            raise PasskeyError(f"Entry '{entry.name}' has no secret fields to share")
        selected_config = dict(clean_entry_config)
        if len(entry.fields) > 1 and is_interactive():
            import questionary

            choices = [
                questionary.Choice(title=k, value=k, checked=True)
                for k in entry.fields
            ]
            selected = questionary.checkbox(
                "Fields to share",
                choices=choices,
                style=PASSKEY_STYLE,
                instruction="(Space to toggle, Enter to confirm)",
            ).ask()
            if not selected:
                print("Cancelled")
                return None
            selected_secrets = {k: entry.fields[k] for k in selected}
        else:
            selected_secrets = dict(entry.fields)

    filtered_entry = Entry(
        name=entry.name,
        fields=selected_secrets,
        config=selected_config,
        source=entry.source,
        policy=entry.policy,
    )

    passphrase: str | None
    if no_passphrase:
        passphrase = None
    elif prompt_passphrase:
        passphrase = _prompt_share_passphrase(
            f"Passphrase (min {MIN_PASSPHRASE_LEN} chars)"
        )
        if len(passphrase) < MIN_PASSPHRASE_LEN:
            raise PasskeyError(
                f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )
        confirm = _prompt_share_passphrase("Confirm passphrase")
        if passphrase != confirm:
            raise PasskeyError("Passphrases do not match")
    else:
        passphrase = generate_passphrase()

    n_fields = len(selected_secrets)
    field_word = "field" if n_fields == 1 else "fields"

    if output_path is not None:
        assert passphrase is not None
        filtered_entry.config["_shared_by"] = shared_by or ""
        filtered_entry.config["_shared_at"] = datetime.now().isoformat()
        written_path = _export_filtered_bundle(
            output_path=output_path,
            entry=filtered_entry,
            passphrase=passphrase,
        )
        size = written_path.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} bytes"
        print(f"Bundle exported to {written_path} ({n_fields} {field_word}, {size_str})")
        if not prompt_passphrase:
            print(f"\n  Passphrase: {passphrase}")
            print("  Share this passphrase separately — it cannot be recovered.")
        print(f"  Recipient runs: passkey upload {output_path}")
        return written_path

    token = encode_share_token(
        filtered_entry,
        passphrase=passphrase,
        shared_by=shared_by,
    )
    log_operation(
        "share_token_create",
        entry_name=entry.name,
        details={
            "field_count": n_fields,
            "shared": True,
            "mode": "embedded_key" if no_passphrase else "passphrase",
        },
    )

    if no_passphrase:
        print(
            "WARNING: --no-passphrase embeds the 256-bit key inside the token. "
            "Anyone who obtains this pk1: string can decrypt it.",
            file=sys.stderr,
        )

    timeout_sec = 60 if no_passphrase else 120
    copied = False
    if not no_copy:
        try:
            copy_with_autoclear(token, timeout_seconds=timeout_sec)
            copied = True
        except Exception:
            copied = False

    if copied:
        print(
            f"Shared '{entry.name}' ({n_fields} {field_word}, {len(token)} chars) "
            f"— pk1: token copied to clipboard (auto-clears in {timeout_sec}s)"
        )
    else:
        print(f"Shared '{entry.name}' ({n_fields} {field_word}, {len(token)} chars):")
        print(f"\n  {token}\n")

    if passphrase is not None and not prompt_passphrase:
        print(f"\n  Passphrase: {passphrase}")
        print("  Share this passphrase separately — it cannot be recovered.")
    print("  Recipient runs: passkey upload")
    return token


def _export_filtered_bundle(
    output_path: str,
    entry: Entry,
    passphrase: str,
) -> Path:
    """Export a single filtered entry as a legacy PK01 encrypted bundle (O_EXCL, 0o600)."""
    path = Path(output_path).expanduser()
    if path.exists():
        raise PasskeyError(f"File already exists: {path}")

    entries_data = [entry.to_export_dict()]
    payload = json.dumps(
        {
            "version": "1.0",
            "entry_count": len(entries_data),
            "entries": entries_data,
        }
    ).encode("utf-8")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    header = MAGIC + struct.pack(">I", FORMAT_VERSION)

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(header)
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)
    except BaseException:
        os.unlink(path)
        raise

    log_operation("bundle_export", entry_name=entry.name, details={"count": 1, "shared": True})
    return path


def _decrypt_pk01_entries(
    data: bytes,
    raw_phrase: str,
    norm_phrase: str,
) -> list[tuple[Entry, dict]]:
    """Decrypt a PK01 binary bundle into (Entry, meta) pairs for preview and collision handling."""
    min_size = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN + _GCM_TAG_LEN
    if len(data) < min_size:
        raise PasskeyError("Invalid bundle file: too small")
    if data[:4] != MAGIC:
        raise PasskeyError("Invalid bundle file: not a passkey bundle")
    version = struct.unpack(">I", data[4:8])[0]
    if version != FORMAT_VERSION:
        raise PasskeyError(f"Unsupported bundle version: {version}")

    offset = 8
    salt = data[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = data[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = data[offset:]

    key = _derive_key(norm_phrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        if norm_phrase != raw_phrase:
            try:
                alt_key = _derive_key(raw_phrase, salt)
                plaintext = AESGCM(alt_key).decrypt(nonce, ciphertext, None)
            except Exception:
                raise PasskeyError(
                    "Import failed: Decryption failed: wrong passphrase or corrupted bundle"
                ) from None
        else:
            raise PasskeyError(
                "Import failed: Decryption failed: wrong passphrase or corrupted bundle"
            ) from None

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise PasskeyError(f"Invalid bundle payload: {e}") from e

    raw_entries = payload.get("entries", [])
    if not raw_entries:
        raise PasskeyError("Bundle contains no entries")

    decoded: list[tuple[Entry, dict]] = []
    for item in raw_entries:
        name = item.get("name")
        fields = item.get("fields", {})
        raw_cfg = dict(item.get("config") or {})
        shared_by = raw_cfg.pop("_shared_by", None) or None
        shared_at = raw_cfg.pop("_shared_at", None) or None
        if not name or not fields or not is_valid_name(name):
            continue
        raw_policy = item.get("policy")
        policy = raw_policy if raw_policy in VALID_POLICIES else "allow"
        ent = Entry(
            name=name,
            fields=dict(fields),
            config=raw_cfg,
            source="bundle-import",
            policy=policy,
        )
        decoded.append((ent, {"shared_by": shared_by, "shared_at": shared_at}))

    if not decoded:
        raise PasskeyError("Bundle contains no valid entries")
    return decoded


def _print_share_preview(entry: Entry, meta: dict) -> None:
    """Display non-sensitive preview of an incoming shared entry before saving."""
    from .interactive import format_secret_preview

    print(f"\n  Shared entry: {entry.name}")
    if meta.get("shared_by") or meta.get("shared_at"):
        by_part = meta.get("shared_by") or "teammate"
        at_part = f" ({meta['shared_at']})" if meta.get("shared_at") else ""
        print(f"  Shared by:    {by_part}{at_part}")
    print(f"  Policy:       {entry.policy}")
    print("  Fields:")
    key_w = max(len(k) for k in entry.fields)
    for k in sorted(entry.fields):
        print(f"    {k:<{key_w}}  {format_secret_preview(entry.fields[k])}")
    if entry.config:
        print(f"  Config keys:  {', '.join(sorted(entry.config))}")
    print()


def _apply_uploaded_entry(
    entry: Entry,
    meta: dict,
    *,
    as_name: str | None = None,
    mode: str = "ask",
    audit_op: str = "share_upload",
) -> dict:
    """Preview incoming entry, resolve collisions preserving existing metadata, and save."""
    from .interactive import PASSKEY_STYLE, is_interactive

    target_name = _validate_entry_name(as_name or entry.name)
    entry.name = target_name

    _print_share_preview(entry, meta)

    existing = get_entry(target_name)
    effective_mode = mode

    while existing is not None and effective_mode == "ask":
        if not is_interactive():
            raise PasskeyError(
                f"Entry '{target_name}' already exists. "
                "Pass --mode merge, --mode overwrite, --mode skip, or --as <new_name>.",
                error_code="ENTRY_EXISTS",
                entry=target_name,
            )
        import questionary

        action = questionary.select(
            f"Entry '{target_name}' already exists. How would you like to proceed?",
            choices=[
                questionary.Choice(
                    f"Merge / update fields into '{target_name}'", value="merge"
                ),
                questionary.Choice(f"Overwrite '{target_name}'", value="overwrite"),
                questionary.Choice("Save as a new entry name...", value="rename"),
                questionary.Choice("Cancel", value="cancel"),
            ],
            style=PASSKEY_STYLE,
            use_jk_keys=False,
        ).ask()

        if action in (None, "cancel"):
            print("Cancelled")
            return {
                "created": 0,
                "updated": 0,
                "skipped": 1,
                "entry": target_name,
                "status": "cancelled",
            }

        if action == "rename":
            raw_new = questionary.text("New entry name:", style=PASSKEY_STYLE).ask()
            if not raw_new or not raw_new.strip():
                print("Cancelled")
                return {
                    "created": 0,
                    "updated": 0,
                    "skipped": 1,
                    "entry": target_name,
                    "status": "cancelled",
                }
            target_name = _validate_entry_name(raw_new)
            entry.name = target_name
            existing = get_entry(target_name)
            continue

        effective_mode = action
        break

    n_fields = len(entry.fields)
    field_word = "field" if n_fields == 1 else "fields"

    if existing is None:
        save_entry(entry, is_update=False)
        log_operation(
            audit_op,
            entry_name=target_name,
            details={
                "created": 1,
                "updated": 0,
                "skipped": 0,
                "field_count": n_fields,
                "shared": True,
                "mode": "create",
            },
        )
        print(f"Saved '{target_name}' to keychain ({n_fields} {field_word}).")
        return {
            "created": 1,
            "updated": 0,
            "skipped": 0,
            "entry": target_name,
            "status": "created",
        }

    if effective_mode == "skip":
        log_operation(
            audit_op,
            entry_name=target_name,
            details={
                "created": 0,
                "updated": 0,
                "skipped": 1,
                "shared": True,
                "mode": "skip",
            },
        )
        print(f"Skipped '{target_name}' (already exists).")
        return {
            "created": 0,
            "updated": 0,
            "skipped": 1,
            "entry": target_name,
            "status": "skipped",
        }

    if effective_mode == "merge":
        # Landmine #3: preserve existing created, policy, source, last_rotated, config & unshared fields
        existing.merge_fields(entry.fields)
        config_changed = False
        for ck, cv in entry.config.items():
            if existing.config.get(ck) != cv:
                existing.config[ck] = cv
                config_changed = True
        if config_changed:
            existing.touch()
        save_entry(existing, is_update=True)
        log_operation(
            audit_op,
            entry_name=target_name,
            details={
                "created": 0,
                "updated": 1,
                "skipped": 0,
                "field_count": n_fields,
                "shared": True,
                "mode": "merge",
            },
        )
        print(f"Merged {n_fields} {field_word} into '{target_name}'.")
        return {
            "created": 0,
            "updated": 1,
            "skipped": 0,
            "entry": target_name,
            "status": "merged",
        }

    if effective_mode == "overwrite":
        # Landmine #3: replace secret fields while preserving created, policy, source, last_rotated & unshared config
        existing.fields = dict(entry.fields)
        existing.config = {**existing.config, **entry.config}
        existing.touch()
        save_entry(existing, is_update=True)
        log_operation(
            audit_op,
            entry_name=target_name,
            details={
                "created": 0,
                "updated": 1,
                "skipped": 0,
                "field_count": n_fields,
                "shared": True,
                "mode": "overwrite",
            },
        )
        print(f"Overwrote '{target_name}' ({n_fields} {field_word}).")
        return {
            "created": 0,
            "updated": 1,
            "skipped": 0,
            "entry": target_name,
            "status": "overwritten",
        }

    raise PasskeyError(f"Unsupported upload mode: '{effective_mode}'", error_code="INVALID_USAGE")


def cmd_upload(
    file_path: str | None = None,
    *,
    as_name: str | None = None,
    mode: str = "ask",
) -> dict:
    """Import a shared entry from an interactive pk1:... token paste or a .enc bundle file."""
    from .interactive import prompt_secret

    guard_no_token_in_argv(file_path)

    if mode not in ("ask", "skip", "overwrite", "merge"):
        raise PasskeyError(
            f"Invalid collision mode '{mode}'. Choose from: ask, skip, overwrite, merge",
            error_code="INVALID_USAGE",
        )

    if as_name is not None:
        as_name = _validate_entry_name(as_name)

    if file_path is None:
        raw_input = prompt_secret("Paste pk1:... token (or .enc file path)")
        candidate = raw_input.strip().strip("'\"`").strip()
        if not candidate:
            raise PasskeyError("No share token or bundle file provided")
        compact = re.sub(r"\s+", "", candidate)
        if compact.startswith(TOKEN_PREFIX):
            entry, meta = decode_share_token(candidate)
            return _apply_uploaded_entry(entry, meta, as_name=as_name, mode=mode)
        file_path = candidate

    path = Path(file_path).expanduser()
    if not path.exists():
        raise PasskeyError(f"File not found: {path}")

    check_file_permissions(path)
    data = path.read_bytes()

    if data.lstrip().startswith(b"pk1:"):
        entry, meta = decode_share_token(data.decode("utf-8", errors="strict"))
        return _apply_uploaded_entry(entry, meta, as_name=as_name, mode=mode)

    if len(data) < 8:
        raise PasskeyError("Invalid bundle file: too small")
    if data[:4] != MAGIC:
        raise PasskeyError("Invalid bundle file: not a passkey bundle")

    raw_phrase = _prompt_share_passphrase("Passphrase")
    norm_phrase = normalize_passphrase(raw_phrase)

    min_pk01_size = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN + _GCM_TAG_LEN
    if import_bundle is not _ORIG_IMPORT_BUNDLE or len(data) < min_pk01_size:
        fallback_mode = "skip" if mode == "ask" else mode
        try:
            result = import_bundle(str(path), passphrase=norm_phrase, mode=fallback_mode)
        except PasskeyError as e:
            raise PasskeyError(f"Import failed: {e}") from e
        print(
            f"\nImport complete: {result['created']} created, "
            f"{result['updated']} updated, {result['skipped']} skipped"
        )
        return result

    decoded_entries = _decrypt_pk01_entries(data, raw_phrase, norm_phrase)
    if as_name is not None and len(decoded_entries) > 1:
        raise PasskeyError(
            "'--as' can only be used when importing a single-entry bundle",
            error_code="INVALID_USAGE",
        )

    totals = {"created": 0, "updated": 0, "skipped": 0}
    last_res: dict = {}
    for ent, meta in decoded_entries:
        last_res = _apply_uploaded_entry(
            ent,
            meta,
            as_name=as_name,
            mode=mode,
            audit_op="bundle_import",
        )
        totals["created"] += int(last_res.get("created", 0))
        totals["updated"] += int(last_res.get("updated", 0))
        totals["skipped"] += int(last_res.get("skipped", 0))

    if len(decoded_entries) > 1:
        print(
            f"\nImport complete: {totals['created']} created, "
            f"{totals['updated']} updated, {totals['skipped']} skipped"
        )
        return totals
    return last_res


def cmd_receive(
    bundle_path: str | None = None,
    *,
    as_name: str | None = None,
    mode: str = "ask",
) -> dict:
    """Backwards-compatible alias for cmd_upload supporting both pk1: paste and .enc files."""
    return cmd_upload(bundle_path, as_name=as_name, mode=mode)
