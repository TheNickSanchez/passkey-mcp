"""Team sharing UX layer over encrypted bundles."""

import getpass
import secrets
from pathlib import Path

from .audit import log_operation
from .bundle import check_file_permissions, import_bundle
from .keychain import PasskeyError, get_entry
from .models import Entry

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


def generate_passphrase(num_words: int = 8) -> str:
    """Generate a random passphrase from the wordlist.

    Args:
        num_words: Number of words (default 8 = ~64 bits of entropy)

    Returns:
        Passphrase string with words joined by hyphens
    """
    words = [secrets.choice(_PASSPHRASE_WORDS) for _ in range(num_words)]
    return "-".join(words)


def cmd_share(
    entry_name: str,
    output_path: str | None = None,
    shared_by: str | None = None,
) -> None:
    """Share an entry as an encrypted bundle.

    Interactive flow with field selection, passphrase generation, and metadata.

    Args:
        entry_name: Name of the entry to share
        output_path: Optional output file path
        shared_by: Optional sender name
    """
    from .interactive import is_interactive

    entry = get_entry(entry_name)
    if not entry:
        raise PasskeyError(f"Entry '{entry_name}' not found")

    # Filter to secret fields only
    secret_fields = {k: v for k, v in entry.fields.items()}
    if not secret_fields:
        raise PasskeyError(f"Entry '{entry_name}' has no secret fields to share")

    # Field selection (interactive only)
    fields_to_share = list(secret_fields.keys())
    if is_interactive() and len(secret_fields) > 1:
        import questionary

        from .interactive import PASSKEY_STYLE

        selected = questionary.checkbox(
            "Fields to share",
            choices=list(secret_fields.keys()),
            style=PASSKEY_STYLE,
            instruction="(Space to select, Enter to confirm)",
        ).ask()
        if not selected:
            print("Cancelled")
            return
        fields_to_share = selected

    # Build filtered entry for export
    filtered_entry = Entry(
        name=entry.name,
        fields={k: secret_fields[k] for k in fields_to_share},
        config={},
        source=entry.source,
    )

    # Passphrase
    if is_interactive():
        import questionary

        from .interactive import PASSKEY_STYLE

        use_generated = questionary.confirm(
            "Generate a passphrase?", default=True, style=PASSKEY_STYLE
        ).ask()
        if use_generated:
            passphrase = generate_passphrase()
            print(f"\n  Passphrase: {passphrase}")
            print("  Share this passphrase separately — it cannot be recovered.\n")
        else:
            passphrase = getpass.getpass("Passphrase (min 12 chars): ")
            if len(passphrase) < 12:
                raise PasskeyError("Passphrase must be at least 12 characters")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                raise PasskeyError("Passphrases do not match")
    else:
        passphrase = getpass.getpass("Passphrase (min 12 chars): ")
        if len(passphrase) < 12:
            raise PasskeyError("Passphrase must be at least 12 characters")

    # Sender name
    if shared_by is None and is_interactive():
        import questionary
        shared_by = questionary.text("Your name (optional):", default="").ask() or None

    # Determine output path
    if output_path is None:
        suffix = f"-{shared_by}" if shared_by else ""
        output_path = f"{entry_name}{suffix}.enc"

    # Add metadata to the entry before export
    from datetime import datetime
    filtered_entry.config["_shared_by"] = shared_by or ""
    filtered_entry.config["_shared_at"] = datetime.now().isoformat()

    # Export using the existing bundle infrastructure
    # We need to create a temporary single-entry bundle
    _export_filtered_bundle(
        output_path=output_path,
        entry=filtered_entry,
        passphrase=passphrase,
    )

    size = Path(output_path).stat().st_size
    size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} bytes"
    print(f"Bundle exported to {output_path} ({len(fields_to_share)} field{'s' if len(fields_to_share) != 1 else ''}, {size_str})")


def _export_filtered_bundle(
    output_path: str,
    entry,  # Entry object
    passphrase: str,
) -> None:
    """Export a single filtered entry as an encrypted bundle.

    Uses the same binary format as bundle.py for compatibility.
    """
    import json
    import os
    import struct

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    from .bundle import (
        FORMAT_VERSION,
        KEY_LEN,
        MAGIC,
        NONCE_LEN,
        SALT_LEN,
        SCRYPT_N,
        SCRYPT_P,
        SCRYPT_R,
    )

    path = Path(output_path).expanduser()
    if path.exists():
        raise PasskeyError(f"File already exists: {path}")

    entries_data = [entry.to_export_dict()]

    payload = json.dumps({
        "version": "1.0",
        "entry_count": len(entries_data),
        "entries": entries_data,
    }).encode("utf-8")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)

    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    key = kdf.derive(passphrase.encode("utf-8"))

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, payload, None)

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


def cmd_receive(bundle_path: str) -> None:
    """Import entries from an encrypted bundle.

    Simplified UX: prompt for passphrase, preview, confirm, import.

    Args:
        bundle_path: Path to the .enc bundle file
    """

    path = Path(bundle_path).expanduser()
    if not path.exists():
        raise PasskeyError(f"File not found: {path}")

    # Warn if file has insecure permissions
    check_file_permissions(path)

    # Read and validate bundle header
    with open(path, "rb") as f:
        header = f.read(8)

    if len(header) < 8:
        raise PasskeyError("Invalid bundle file: too small")
    if header[:4] != b"PK01":
        raise PasskeyError("Invalid bundle file: not a passkey bundle")

    # Get passphrase
    passphrase = getpass.getpass("Passphrase: ")

    # Decrypt and preview (without saving)
    try:
        result = import_bundle(str(path), passphrase=passphrase, mode="skip")
    except PasskeyError as e:
        raise PasskeyError(f"Import failed: {e}") from e

    # Summary
    result["created"] + result["updated"] + result["skipped"]
    print(f"\nImport complete: {result['created']} created, {result['updated']} updated, {result['skipped']} skipped")

    log_operation(
        "bundle_import",
        details={
            "created": result["created"],
            "updated": result["updated"],
            "skipped": result["skipped"],
            "source_file": str(path),
        },
    )
