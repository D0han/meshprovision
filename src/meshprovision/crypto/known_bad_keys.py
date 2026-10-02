"""The on-disk key blocklist: loading, caching, and parsing.

Split out of :mod:`meshprovision.crypto.weakkeys` (which was growing too
large) because this is infrastructure -- locating, reading, and caching
the operator-maintained ``known_bad_keys.txt`` blocklist file -- and is
conceptually distinct from the weak-key auditing logic in that module
which consumes it. Also holds :data:`SMALL_ORDER_POINTS`, the 7
canonical libsodium X25519 small-order points that
:func:`load_known_bad_keys` always includes, whether or not an on-disk
file is present.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Final

from meshprovision.crypto import keys
from meshprovision.errors import KeyMaterialError, SettingsError

__all__ = [
    "KNOWN_BAD_KEYS_ENV",
    "SMALL_ORDER_POINTS",
    "default_known_bad_keys_path",
    "load_known_bad_keys",
    "parse_known_bad_keys",
]

_logger = logging.getLogger(__name__)

KNOWN_BAD_KEYS_ENV: Final[str] = "MESHPROVISION_KNOWN_BAD_KEYS"
"""Environment variable overriding the blocklist file path."""

# The 7 canonical X25519 small-order / degenerate public keys from
# libsodium's has_small_order() blocklist
# (crypto_scalarmult/curve25519/ref10/x25519_ref10.c), decoded from the
# same base64 encodings committed verbatim to data/known_bad_keys.txt so
# the two files can never silently drift apart. p = 2**255 - 19; all
# encodings are little-endian 32-byte.
_SMALL_ORDER_ALL_ZERO = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
)
"""The all-zero point (order 4). Also the firmware's own weak-key check."""

_SMALL_ORDER_POINT_ONE = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
)
"""The point 1 (order 1): 0x01 followed by 31 zero bytes."""

_SMALL_ORDER_8_A = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
"""Order-8 point #1 (libsodium blacklist entry 3)."""

_SMALL_ORDER_8_B = bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
"""Order-8 point #2 (libsodium blacklist entry 4)."""

_SMALL_ORDER_P_MINUS_1 = bytes.fromhex(
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)
"""p - 1 (order 2)."""

_SMALL_ORDER_P = bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
"""p (order 4) -- the field modulus itself, a non-canonical encoding of 0."""

_SMALL_ORDER_P_PLUS_1 = bytes.fromhex(
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)
"""p + 1 (order 1) -- a non-canonical encoding of 1."""

SMALL_ORDER_POINTS: Final[tuple[bytes, ...]] = (
    _SMALL_ORDER_ALL_ZERO,
    _SMALL_ORDER_POINT_ONE,
    _SMALL_ORDER_8_A,
    _SMALL_ORDER_8_B,
    _SMALL_ORDER_P_MINUS_1,
    _SMALL_ORDER_P,
    _SMALL_ORDER_P_PLUS_1,
)
"""The 7 canonical libsodium X25519 small-order / degenerate public keys.

Every entry is exactly 32 bytes (verified below, at import time). Any
node advertising one of these has a broken or malicious key, and every
shared secret derived from one is degenerate.
"""

if any(len(point) != keys.X25519_KEY_SIZE for point in SMALL_ORDER_POINTS):
    raise KeyMaterialError(
        "SMALL_ORDER_POINTS contains an entry that is not "
        f"{keys.X25519_KEY_SIZE} bytes; this is a packaging bug",
        reason="invalid small-order point table",
    )

_blocklist_cache: dict[tuple[Path, int, int], frozenset[bytes]] = {}
"""Module-private cache of parsed blocklist files, keyed by (path, mtime_ns, size).

Deliberately mutable, unlike the rest of this project's data structures:
this is infrastructure caching, not domain state. Keying on the file's
mtime and size (rather than just its path) means a rewritten blocklist
file is picked up on the next call without ever re-reading an unchanged
one.
"""


def _known_bad_keys_candidates(*, db_path: Path | None = None) -> list[Path]:
    """Build the ordered, non-env candidate list, without checking existence.

    Args:
        db_path: The configured database path, when known. Its parent
            directory is tried first among these candidates.

    Returns:
        The candidates in search order: DB-sibling (if ``db_path`` is
        given), package, repo root (if resolvable), then cwd.
    """
    candidates: list[Path] = []
    if db_path is not None:
        candidates.append(db_path.parent / "known_bad_keys.txt")

    module_parents = Path(__file__).resolve().parents
    package_root = module_parents[1]
    repo_root_candidate = module_parents[3] if len(module_parents) > 3 else None
    candidates.append(package_root / "data" / "known_bad_keys.txt")
    if repo_root_candidate is not None:
        candidates.append(repo_root_candidate / "data" / "known_bad_keys.txt")
    candidates.append(Path.cwd() / "data" / "known_bad_keys.txt")
    return candidates


def default_known_bad_keys_path(*, db_path: Path | None = None) -> Path | None:
    """Resolve the default location of the on-disk key blocklist.

    Tries, in order: the path in :data:`KNOWN_BAD_KEYS_ENV` (if set);
    ``db_path.parent/known_bad_keys.txt`` (if ``db_path`` is given -- the
    database's own directory is stable regardless of the caller's
    current working directory, unlike the ``./data`` fallback below);
    ``<package>/data/known_bad_keys.txt`` (in case the file is ever
    vendored into the installed package); ``<repo root>/data/known_bad_keys.txt``
    (a checkout run from source); ``./data/known_bad_keys.txt`` relative
    to the current working directory.

    The package candidate is deliberately searched *after* the DB
    sibling: a bundled copy must never take priority over an operator's
    own file, or it would permanently hide the operator's additions.

    Args:
        db_path: The configured database path, when known. Passed
            through from :meth:`~meshprovision.cli.common.CliContext.
            known_bad_keys`.

    Returns:
        The first candidate path that exists, or ``None`` if none does
        (this is not an error -- see :func:`load_known_bad_keys`).

    Raises:
        SettingsError: If :data:`KNOWN_BAD_KEYS_ENV` is set to a path
            that does not exist.
    """
    env_value = os.environ.get(KNOWN_BAD_KEYS_ENV)
    if env_value and env_value.strip():
        candidate = Path(env_value.strip()).expanduser()
        if candidate.exists():
            return candidate
        raise SettingsError(
            f"{KNOWN_BAD_KEYS_ENV} is set to a path that does not exist: {candidate}",
            hint=(
                f"Check the path in {KNOWN_BAD_KEYS_ENV}, or unset it to use the bundled blocklist."
            ),
        )

    for candidate in _known_bad_keys_candidates(db_path=db_path):
        if candidate.exists():
            return candidate
    return None


def parse_known_bad_keys(text: str, *, source: str = "<string>") -> tuple[bytes, ...]:
    """Parse the contents of a known-bad-keys blocklist file.

    Pure: performs no I/O. One base64-encoded 32-byte key per line;
    everything from the first ``#`` to end of line is a comment; blank
    lines are ignored.

    Args:
        text: The file contents to parse.
        source: Identifies the file for error messages (never the
            offending token itself).

    Returns:
        The decoded keys, deduplicated preserving first-seen order.

    Raises:
        KeyMaterialError: If any non-comment, non-blank line fails to
            decode to exactly 32 bytes of canonical base64.
    """
    seen: dict[bytes, None] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        raw = keys.decode_key(line, field=f"{source}:{lineno}")
        seen.setdefault(raw, None)
    return tuple(seen)


def load_known_bad_keys(
    path: Path | None = None, *, db_path: Path | None = None
) -> frozenset[bytes]:
    """Load the effective known-bad-keys blocklist.

    Always includes :data:`SMALL_ORDER_POINTS`, whether or not an
    on-disk file is present -- absence of the file is a supported,
    non-error condition. Results are cached in a module-private dict
    keyed by ``(path, mtime_ns, size)``, so repeated audits do not
    re-read the file, but a rewritten file is picked up on the next call.

    Args:
        path: An explicit blocklist path. When ``None``, resolved via
            :func:`default_known_bad_keys_path`.
        db_path: The configured database path, passed through to
            :func:`default_known_bad_keys_path` when ``path`` is
            ``None``, so an installed ``mesh`` run finds a blocklist
            file next to its database regardless of the current
            working directory. Ignored when ``path`` is given.

    Returns:
        The union of :data:`SMALL_ORDER_POINTS` and everything parsed
        from the resolved file (or just :data:`SMALL_ORDER_POINTS` if no
        file was found).

    Raises:
        KeyMaterialError: If the resolved file exists but cannot be read,
            or contains a malformed entry (via :func:`parse_known_bad_keys`).
        SettingsError: If :data:`KNOWN_BAD_KEYS_ENV` is set to a path that
            does not exist (propagated from :func:`default_known_bad_keys_path`).
    """
    resolved = path if path is not None else default_known_bad_keys_path(db_path=db_path)
    if resolved is None or not resolved.exists():
        searched = ", ".join(str(c) for c in _known_bad_keys_candidates(db_path=db_path))
        _logger.info(
            "no known_bad_keys.txt found (looked in: %s); using only the %d built-in "
            "small-order points; set %s to use a custom blocklist",
            searched,
            len(SMALL_ORDER_POINTS),
            KNOWN_BAD_KEYS_ENV,
        )
        return frozenset(SMALL_ORDER_POINTS)

    try:
        stat = resolved.stat()
    except OSError as exc:
        raise KeyMaterialError(
            f"blocklist file could not be read: {resolved}",
            reason="blocklist file could not be read",
        ) from exc

    cache_key = (resolved, stat.st_mtime_ns, stat.st_size)
    cached = _blocklist_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyMaterialError(
            f"blocklist file could not be read: {resolved}",
            reason="blocklist file could not be read",
        ) from exc

    parsed = parse_known_bad_keys(text, source=str(resolved))
    result = frozenset(parsed) | frozenset(SMALL_ORDER_POINTS)
    _blocklist_cache[cache_key] = result
    return result
