"""Real-time secret scrubbing for child-process stdout and stderr streams."""

import json
from collections.abc import Iterable

CONCEALED_TEXT = "<concealed by passkey>"
CONCEALED_BYTES = CONCEALED_TEXT.encode("utf-8")
MIN_SECRET_LEN = 4


def build_secret_patterns(secret_values: Iterable[str]) -> list[bytes]:
    """Build deduplicated byte patterns (raw + JSON-escaped) for secrets >= 4 chars.

    Sorted longest-first so longer secrets take precedence when one secret is a
    prefix of another.
    """
    seen: set[bytes] = set()
    for val in secret_values:
        if not isinstance(val, str) or len(val) < MIN_SECRET_LEN:
            continue
        raw = val.encode("utf-8")
        if len(raw) >= MIN_SECRET_LEN:
            seen.add(raw)
        escaped_str = json.dumps(val)[1:-1]
        escaped = escaped_str.encode("utf-8")
        if len(escaped) >= MIN_SECRET_LEN:
            seen.add(escaped)
    return sorted(seen, key=len, reverse=True)


def scrub_bytes(data: bytes, patterns: list[bytes]) -> bytes:
    """Replace all non-overlapping occurrences of patterns in data.

    Scans left-to-right for the earliest match, breaking ties in favor of the
    longest pattern (patterns must be pre-sorted longest-first).
    """
    if not data or not patterns:
        return data

    out = bytearray()
    pos = 0
    n = len(data)

    while pos < n:
        best_idx = -1
        best_pat: bytes | None = None
        for pat in patterns:
            idx = data.find(pat, pos)
            if idx != -1 and (
                best_idx == -1
                or idx < best_idx
                or (idx == best_idx and best_pat is not None and len(pat) > len(best_pat))
            ):
                best_idx = idx
                best_pat = pat
                if best_idx == pos:
                    # Patterns are sorted longest-first, so a match right at pos cannot be beaten.
                    break

        if best_idx == -1 or best_pat is None:
            out.extend(data[pos:])
            break

        if best_idx > pos:
            out.extend(data[pos:best_idx])
        out.extend(CONCEALED_BYTES)
        pos = best_idx + len(best_pat)

    return bytes(out)


class SecretMasker:
    """Stateful streaming byte scrubber that catches secrets split across chunks.

    Maintains a sliding holdback window bounded by `max_secret_len - 1`. Only
    suffixes that actually match a proper prefix of a registered secret are held
    back, so normal lines and JSON-RPC frames flush immediately with zero delay.
    """

    def __init__(self, secret_values: Iterable[str]) -> None:
        self.patterns = build_secret_patterns(secret_values)
        self.max_secret_len = max((len(p) for p in self.patterns), default=0)
        self.holdback = max(0, self.max_secret_len - 1)
        self._prefixes: frozenset[bytes] = frozenset(
            pat[:k]
            for pat in self.patterns
            for k in range(1, len(pat))
        )
        self._buf = bytearray()

    @property
    def active(self) -> bool:
        """True if at least one secret pattern is registered."""
        return bool(self.patterns)

    def _matching_tail_len(self, data: bytes) -> int:
        """Return length of longest suffix of data (<= holdback) that is a pattern prefix."""
        if not data or not self.holdback or not self._prefixes:
            return 0
        max_check = min(len(data), self.holdback)
        for length in range(max_check, 0, -1):
            if data[-length:] in self._prefixes:
                return length
        return 0

    def feed(self, chunk: bytes) -> bytes:
        """Ingest a byte chunk and return safe, scrubbed bytes ready to emit."""
        if not chunk:
            return b""
        if not self.patterns:
            return chunk

        self._buf.extend(chunk)
        scrubbed = scrub_bytes(bytes(self._buf), self.patterns)
        keep = self._matching_tail_len(scrubbed)
        if keep == 0:
            self._buf.clear()
            return scrubbed

        emit = scrubbed[:-keep]
        self._buf = bytearray(scrubbed[-keep:])
        return emit

    def flush(self) -> bytes:
        """Scrub and emit all remaining buffered bytes (used on idle timeout or EOF)."""
        if not self._buf:
            return b""
        scrubbed = scrub_bytes(bytes(self._buf), self.patterns)
        self._buf.clear()
        return scrubbed
