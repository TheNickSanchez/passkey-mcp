"""Encrypted bundle export/import for portable secret transfer."""

import getpass
import json
import os
import stat
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .audit import log_operation
from .keychain import PasskeyError, get_entry, list_entries, save_entry
from .models import Entry, is_valid_name

MAGIC = b"PK01"
FORMAT_VERSION = 1
SALT_LEN = 32
NONCE_LEN = 12
MIN_PASSPHRASE_LEN = 12

SCRYPT_N = 2**20
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32


def check_file_permissions(
    path: Path, allow_insecure: bool = False, strict: bool = False
) -> None:
    """Check that a file has no group/other permissions.

    Default (strict=False): warn only. With strict=True, raise PasskeyError
    for insecure files unless allow_insecure is set (the --insecure flag).

    This is the single implementation used by bundles, exports, and
    importers alike.
    """
    try:
        mode = path.stat().st_mode
    except Exception:
        return
    if not mode & (stat.S_IRWXG | stat.S_IRWXO):
        return
    if strict and not allow_insecure:
        raise PasskeyError(
            f"'{path}' has insecure permissions ({oct(mode & 0o777)}).\n"
            "  This file may be readable by other users on this system.\n"
            f"  Fix with: chmod 600 '{path}'\n"
            "  Or use --insecure to import anyway."
        )
    print(
        f"WARNING: '{path}' has insecure permissions ({oct(mode & 0o777)}).",
        file=sys.stderr,
    )
    if strict and allow_insecure:
        print("  Proceeding anyway due to --insecure flag.\n", file=sys.stderr)


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from passphrase using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def export_bundle(
    output_path: str,
    entry_names: list[str] | None = None,
    passphrase: str | None = None,
) -> Path:
    """Export entries to an encrypted bundle file.

    Args:
        output_path: Destination file path
        entry_names: Specific entries to export (None = all)
        passphrase: Encryption passphrase (prompted if None)

    Returns:
        Path to created bundle file

    Raises:
        PasskeyError: If Keychain access fails or no entries found
        FileExistsError: If output file already exists
    """
    path = Path(output_path).expanduser()
    if path.exists():
        raise FileExistsError(f"File already exists: {path}")

    all_names = list_entries()
    if not all_names:
        raise PasskeyError("No entries to export")

    if entry_names:
        missing = set(entry_names) - set(all_names)
        if missing:
            raise PasskeyError(f"Entries not found: {', '.join(sorted(missing))}")
        names_to_export = entry_names
    else:
        names_to_export = all_names

    entries_data = []
    for name in names_to_export:
        entry = get_entry(name)
        if entry:
            entries_data.append(entry.to_export_dict())

    if not entries_data:
        raise PasskeyError("No entries could be read from Keychain")

    if passphrase is None:
        passphrase = getpass.getpass("Bundle passphrase (min 12 chars): ")
        if len(passphrase) < MIN_PASSPHRASE_LEN:
            raise PasskeyError(f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
        confirm = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm:
            raise PasskeyError("Passphrases do not match")

    if len(passphrase) < MIN_PASSPHRASE_LEN:
        raise PasskeyError(f"Passphrase must be at least {MIN_PASSPHRASE_LEN} characters")

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

    log_operation("bundle_export", details={"count": len(entries_data)})
    return path


def import_bundle(
    input_path: str,
    passphrase: str | None = None,
    mode: str = "skip",
) -> dict:
    """Import entries from an encrypted bundle file.

    Args:
        input_path: Path to encrypted bundle
        passphrase: Decryption passphrase (prompted if None)
        mode: How to handle existing entries (skip, overwrite, merge)

    Returns:
        Dict with import results: created, updated, skipped counts

    Raises:
        PasskeyError: If decryption fails or bundle is invalid
    """
    path = Path(input_path).expanduser()
    if not path.exists():
        raise PasskeyError(f"File not found: {path}")

    check_file_permissions(path)

    with open(path, "rb") as f:
        data = f.read()

    min_size = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN + 16
    if len(data) < min_size:
        raise PasskeyError("Invalid bundle file: too small")

    magic = data[:4]
    if magic != MAGIC:
        raise PasskeyError("Invalid bundle file: bad magic bytes")

    version = struct.unpack(">I", data[4:8])[0]
    if version != FORMAT_VERSION:
        raise PasskeyError(f"Unsupported bundle version: {version}")

    offset = 8
    salt = data[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = data[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = data[offset:]

    if passphrase is None:
        passphrase = getpass.getpass("Bundle passphrase: ")

    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise PasskeyError("Decryption failed: wrong passphrase or corrupted bundle") from None

    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise PasskeyError(f"Invalid bundle payload: {e}") from e

    entries = payload.get("entries", [])
    if not entries:
        raise PasskeyError("Bundle contains no entries")

    created = 0
    updated = 0
    skipped = 0

    for entry_data in entries:
        name = entry_data.get("name")
        fields = entry_data.get("fields", {})
        config = entry_data.get("config", {})

        if not name or not fields:
            skipped += 1
            continue

        if not is_valid_name(name):
            print(f"  {name}: skipped (invalid entry name)", file=sys.stderr)
            skipped += 1
            continue

        existing = get_entry(name)

        if existing and mode == "skip":
            print(f"  {name}: skipped (exists)")
            skipped += 1
            continue

        if existing and mode == "merge":
            changed = existing.merge_fields(fields)
            for k, v in config.items():
                existing.config[k] = v
            if changed:
                save_entry(existing, is_update=True)
                print(f"  {name}: merged ({len(changed)} fields)")
                updated += 1
            else:
                print(f"  {name}: skipped (no changes)")
                skipped += 1
            continue

        entry = Entry(
            name=name,
            fields=fields,
            config=config,
            source="bundle-import",
        )
        save_entry(entry, is_update=existing is not None)
        action = "updated" if existing else "created"
        print(f"  {name}: {action}")
        if existing:
            updated += 1
        else:
            created += 1

    log_operation(
        "bundle_import", details={"created": created, "updated": updated, "skipped": skipped}
    )

    return {"created": created, "updated": updated, "skipped": skipped}
