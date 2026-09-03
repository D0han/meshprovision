"""Merge candidate X25519 public keys into ``data/known_bad_keys.txt``.

This script exists so that, if the Meshtastic project or the community
ever publishes an actual CVE-2025-52464 key list, an operator can merge
it into the blocklist **without a code change**. It is append-only: the
curated header comments and every existing per-entry provenance comment
in the target file are preserved verbatim, and new entries are always
added in a clearly-marked block at the end.

The target file holds **public** keys only -- never submit private key
material as a ``--source``.

Usage:
    python scripts/update_known_bad_keys.py --source new_keys.txt --comment "provenance note"
    python scripts/update_known_bad_keys.py --source new_keys.txt --dry-run
    python scripts/update_known_bad_keys.py --source new_keys.txt --check

Exit codes:
    0: success, or a no-op (nothing new to add).
    1: ``--check`` found new keys not yet in the target (nothing written).
    2: usage or validation error.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from collections.abc import Sequence
from pathlib import Path


def _ensure_package_importable() -> None:
    """Insert the repo's ``src`` directory on ``sys.path`` if needed.

    Lets this script run against a bare checkout, before an editable
    install (``pip install -e .``) has been performed.
    """
    try:
        import meshprovision  # noqa: F401
    except ImportError:
        repo_root = Path(__file__).resolve().parents[1]
        src_dir = repo_root / "src"
        if src_dir.is_dir() and str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))


_ensure_package_importable()

from meshprovision.crypto import keys as crypto_keys  # noqa: E402
from meshprovision.crypto import weakkeys  # noqa: E402
from meshprovision.db import locking  # noqa: E402
from meshprovision.errors import KeyMaterialError, MeshprovisionError  # noqa: E402

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        The configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="update_known_bad_keys.py",
        description=(
            "Merge candidate X25519 public keys into data/known_bad_keys.txt, "
            "append-only, without a code change. The target file holds PUBLIC "
            "keys only -- never pass private key material as --source."
        ),
    )
    parser.add_argument(
        "--source",
        required=True,
        help="File of candidate keys (one per line, '#' comments allowed), or '-' for stdin.",
    )
    parser.add_argument(
        "--format",
        choices=("auto", "base64", "hex"),
        default="auto",
        help=(
            "Encoding of the candidate keys. 'auto' (default) treats a 64-char "
            "all-hex token as hex and everything else as base64."
        ),
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=None,
        help=(
            "Blocklist file to update. Defaults to the resolved default "
            "known_bad_keys.txt location."
        ),
    )
    parser.add_argument(
        "--comment",
        default=None,
        help="Provenance note recorded above the merged block.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be added; write nothing.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if the source contains any key not already in the target; write nothing.",
    )
    return parser


def _resolve_target(target: Path | None) -> Path:
    """Resolve the blocklist file path to update.

    Args:
        target: An explicit ``--target`` path, or ``None``.

    Returns:
        ``target`` if given; otherwise
        :func:`meshprovision.crypto.weakkeys.default_known_bad_keys_path`;
        otherwise ``<repo root>/data/known_bad_keys.txt``.
    """
    if target is not None:
        return target
    default = weakkeys.default_known_bad_keys_path()
    if default is not None:
        return default
    repo_root = Path(__file__).resolve().parents[1]
    return repo_root / "data" / "known_bad_keys.txt"


def _is_all_hex(token: str) -> bool:
    """Check whether every character of ``token`` is a hex digit.

    Args:
        token: The candidate string.

    Returns:
        ``True`` if ``token`` is non-empty and every character is a hex digit.
    """
    return len(token) > 0 and all(c in _HEX_DIGITS for c in token)


def _decode_candidate(token: str, fmt: str, *, field: str) -> bytes:
    """Decode one candidate key token to 32 raw bytes.

    Args:
        token: The candidate token, already stripped of comments and
            surrounding whitespace.
        fmt: ``"auto"``, ``"base64"``, or ``"hex"``.
        field: Identifies the offending token in error messages -- the
            token's line number and source, never the token itself.

    Returns:
        The decoded 32-byte key.

    Raises:
        KeyMaterialError: If ``token`` cannot be decoded to exactly 32
            bytes in the requested (or auto-detected) format.
    """
    use_hex = fmt == "hex" or (fmt == "auto" and len(token) == 64 and _is_all_hex(token))
    if use_hex:
        try:
            raw = bytes.fromhex(token)
        except ValueError as exc:
            raise KeyMaterialError(f"{field} is not valid hex", reason=str(exc)) from exc
        if len(raw) != crypto_keys.X25519_KEY_SIZE:
            raise KeyMaterialError(
                f"{field} must decode to exactly {crypto_keys.X25519_KEY_SIZE} bytes",
                reason="invalid decoded length",
                expected_length=crypto_keys.X25519_KEY_SIZE,
                actual_length=len(raw),
            )
        return raw
    return crypto_keys.decode_key(token, field=field)


def _read_candidate_tokens(source: str) -> list[str]:
    """Read and comment-strip candidate key tokens from a file or stdin.

    Args:
        source: A file path, or ``"-"`` to read from stdin.

    Returns:
        The non-blank, comment-stripped tokens, in file order.

    Raises:
        MeshprovisionError: If ``source`` names a file that cannot be read.
    """
    try:
        text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    except OSError as exc:
        raise MeshprovisionError(f"could not read source file: {source}") from exc

    tokens: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            tokens.append(line)
    return tokens


def _append_block(target: Path, new_keys: list[bytes], *, comment: str | None, source: str) -> None:
    """Append newly-approved keys to ``target``, preserving everything already there.

    Writes atomically: the full new content is built in memory and
    written to a temp file in ``target``'s own directory, then
    :meth:`Path.replace` moves it onto ``target`` -- so a crash mid-write
    can never corrupt the curated header or existing entries, and lines
    already in the file are never reordered, rewritten, or dropped.

    Args:
        target: Path to the blocklist file to update.
        new_keys: The 32-byte keys to append, already confirmed absent
            from ``target``.
        comment: Provenance note to record above the merged block.
        source: Description of where ``new_keys`` came from, recorded in
            the merged-block header.

    Raises:
        MeshprovisionError: If the file cannot be written.
    """
    existing_text = target.read_text(encoding="utf-8") if target.exists() else ""
    today = dt.datetime.now(dt.UTC).date().isoformat()

    block_lines = [
        "",
        f"# --- Merged {today} from {source} ---",
        f"# {comment or 'no provenance supplied'}",
        *(crypto_keys.encode_key(raw) for raw in new_keys),
    ]
    block = "\n".join(block_lines) + "\n"

    new_content = existing_text
    if new_content and not new_content.endswith("\n"):
        new_content += "\n"
    new_content += block

    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.parent / f".{target.name}.tmp"
        tmp_path.write_text(new_content, encoding="utf-8")
        tmp_path.replace(target)
    except OSError as exc:
        raise MeshprovisionError(f"could not write blocklist file: {target}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Run the update-known-bad-keys CLI.

    Args:
        argv: Command-line arguments, excluding the program name. When
            ``None``, taken from ``sys.argv``.

    Returns:
        The process exit code: ``0`` on success or no-op, ``1`` if
        ``--check`` found new keys, ``2`` on a usage or validation error.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        target = _resolve_target(args.target)
        tokens = _read_candidate_tokens(args.source)
        decoded: list[bytes] = []
        seen_in_source: set[bytes] = set()
        for lineno, token in enumerate(tokens, start=1):
            raw = _decode_candidate(token, args.format, field=f"{args.source}:{lineno}")
            if raw not in seen_in_source:
                seen_in_source.add(raw)
                decoded.append(raw)

        # Held across the read-decide-write sequence below: two concurrent
        # invocations each computing "new" keys from their own independent
        # read of `target` would otherwise race, and the second writer's
        # _append_block call could silently clobber the first's just-merged
        # block (last-writer-wins on the temp-file-then-replace).
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise MeshprovisionError(f"could not create directory for: {target}") from exc
        with locking.exclusive_lock(target):
            existing_text = target.read_text(encoding="utf-8") if target.exists() else ""
            existing = set(weakkeys.parse_known_bad_keys(existing_text, source=str(target)))

            new_keys = [raw for raw in decoded if raw not in existing]
            already_present = len(decoded) - len(new_keys)
            print(f"read {len(decoded)}, new {len(new_keys)}, already present {already_present}")

            if args.check:
                return 1 if new_keys else 0
            if not new_keys:
                return 0
            if args.dry_run:
                for raw in new_keys:
                    print(crypto_keys.encode_key(raw))
                return 0

            _append_block(target, new_keys, comment=args.comment, source=args.source)
        return 0
    except MeshprovisionError as exc:
        print(exc.user_message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
