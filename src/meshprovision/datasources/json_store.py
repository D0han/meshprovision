"""Small JSON files kept next to the HTTP cache: read tolerantly, replaced atomically.

The lorastats region memo and the cached lorastats region list are hints
that can always be rebuilt, so neither may ever stop a run: a file that is
missing, unreadable, oversized or not JSON reads as ``None``, and a failed
write is skipped. Both are logged at DEBUG, never raised. A write goes to a
temp file created owner-only (the cache directory holds node data) and
replaces the target in one ``os.replace``, so a reader never sees half a
file.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import uuid
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["read_json", "write_json"]

_logger = logging.getLogger(__name__)

_FILE_MODE: Final[int] = 0o600
_DIR_MODE: Final[int] = 0o700


def read_json(path: Path, *, max_bytes: int, what: str) -> Any:
    """Read and decode one JSON file, or ``None`` when that is not possible.

    Args:
        path: The file.
        max_bytes: The largest file read; a larger one is ignored.
        what: What the file is, for the DEBUG log.

    Returns:
        The decoded value, or ``None`` when the file is missing (silently),
        cannot be read, is larger than ``max_bytes``, or is not JSON.
    """
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        _logger.debug("could not read the %s %s: %s", what, path, exc)
        return None
    if len(raw) > max_bytes:
        _logger.debug("ignoring the %s %s: too large", what, path)
        return None
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as exc:
        _logger.debug("ignoring the %s %s: %s", what, path, exc)
        return None


def write_json(path: Path, document: object, *, what: str) -> None:
    """Replace ``path`` with ``document`` as JSON, atomically; never raises.

    The parent directory is created owner-only when missing, the file
    owner-only.

    Args:
        path: The file.
        document: A JSON-serializable value.
        what: What the file is, for the DEBUG log.
    """
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(document).encode("utf-8"))
        tmp.replace(path)
    except OSError as exc:
        _logger.debug("could not write the %s %s: %s", what, path, exc)
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
