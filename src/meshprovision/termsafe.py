r"""Escape terminal control sequences out of untrusted display strings.

Rich's ``Console.print`` strips a handful of control characters (BEL,
BS, VT, FF, CR) but passes ESC (``\\x1b``) and the single-byte C1
controls (``\\x80``-``\\x9f``, including the single-byte CSI ``\\x9b``)
straight through. A string built from those bytes -- an OSC 52 clipboard
write, an OSC 8 hyperlink/title spoof, or a cursor-repositioning CSI
sequence -- reaches the operator's real terminal verbatim if it is ever
printed unescaped.

This module is the single place that turns such a string into one that
is safe to print: every C0/C1 control character (and the Unicode
bidi-override controls, which can visually reorder surrounding text) is
replaced by a visible ``\\xNN``/``\\uNNNN`` escape. Everything else,
including non-Latin scripts and emoji, passes through untouched.
:func:`json_dumps_safe` does the same for a JSON document printed to the
terminal (``--json``), using JSON's own ``\\uNNNN`` escapes so the
document still decodes to the original strings.

A pure leaf: no imports beyond the standard library, so every other
module can depend on it without risking an import cycle.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable
from typing import Final

__all__ = ["json_dumps_safe", "terminal_safe"]

_BIDI_CONTROLS: Final[frozenset[str]] = frozenset(
    chr(codepoint) for codepoint in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))
)
"""Unicode bidi-override/isolate controls (U+202A-U+202E, U+2066-U+2069).

Not in Unicode category ``Cc``, but capable of visually reordering or
hiding surrounding text on a terminal that honours them.
"""

_JSON_UNESCAPED_CONTROLS: Final[re.Pattern[str]] = re.compile(
    "[\x7f-\x9f" + "".join(sorted(_BIDI_CONTROLS)) + "]"
)
"""What ``json.dumps(ensure_ascii=False)`` writes raw but :func:`terminal_safe` escapes.

DEL, the C1 controls (U+007F-U+009F) and the bidi controls; JSON itself
already requires the C0 controls (below U+0020) to be escaped.
"""

_KEPT_WITH_NEWLINES: Final[frozenset[str]] = frozenset({"\n", "\t"})
"""Control characters preserved literally when ``allow_newlines`` is set."""


def terminal_safe(text: str, *, allow_newlines: bool = False) -> str:
    r"""Escape every control character in ``text`` that could reach a real terminal.

    Args:
        text: The string to make safe to print.
        allow_newlines: When set, ``\\n`` and ``\\t`` are kept literal
            instead of being escaped -- for multi-line operator-facing
            messages. Every other control character is still escaped.

    Returns:
        ``text`` with every Unicode category ``Cc`` character (C0
        controls, DEL, and the C1 controls U+0080-U+009F) and every bidi
        control replaced by a visible ``\\xNN`` (or ``\\uNNNN`` for the
        bidi controls, which fall outside one byte) escape. All other
        characters, including non-ASCII printable text, are unchanged.
    """
    kept = _KEPT_WITH_NEWLINES if allow_newlines else frozenset[str]()
    escaped: list[str] = []
    for char in text:
        if char in kept:
            escaped.append(char)
        elif unicodedata.category(char) == "Cc" or char in _BIDI_CONTROLS:
            codepoint = ord(char)
            escaped.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def json_dumps_safe(
    obj: object, *, indent: int | None = None, default: Callable[[object], object] | None = None
) -> str:
    r"""Serialize ``obj`` as JSON that is safe to print to a real terminal.

    Like ``json.dumps(obj, ensure_ascii=False)`` -- non-ASCII text such as
    ``"Łódź"`` or emoji stays readable -- except that DEL, the C1 controls
    and the bidi controls are written as ``\uNNNN`` escapes instead of
    raw, so a device- or file-sourced string can't smuggle a terminal
    control sequence (e.g. the single-byte CSI U+009B) into ``--json``
    output. The escapes are standard JSON: the document decodes to
    exactly the same value. Those characters can only appear inside
    string literals (keys included), never in JSON's ASCII structure,
    and a literal backslash before one is already doubled by ``json``,
    so replacing them in the serialized text is safe.

    Args:
        obj: The value to serialize.
        indent: Passed to ``json.dumps``.
        default: Passed to ``json.dumps``: called for any value it can't
            natively encode; None keeps its ``TypeError``.

    Returns:
        The JSON document.
    """
    text = json.dumps(obj, indent=indent, ensure_ascii=False, default=default)
    return _JSON_UNESCAPED_CONTROLS.sub(lambda match: f"\\u{ord(match.group()):04x}", text)
