"""The single choke point for secret material in meshprovision.

Nothing in this project ever renders raw X25519 key bytes, base64-encoded
key strings, channel PSKs, or BLE PINs in a log line, an exception
message, or a ``repr()``. Every place that must hold such a value in
memory wraps it in :class:`SecretBytes`, whose ``__repr__``/``__str__``/
``__format__`` deliberately never expose the wrapped bytes; every place
that must *name* a secret for logging or error reporting uses
:func:`fingerprint` or :func:`redact` to produce a short, non-reversible
digest string instead.

:func:`redact_processor` is a ``structlog`` processor that applies this
policy to an entire log event. It must be installed as the **last**
processor before the renderer in the application's structlog
configuration (see ``cli/logging_setup.py``), so that every other processor's
output (including any that flatten nested structures into strings) still
passes through this one before anything is written out.

This module is a leaf: it imports only the standard library plus
:mod:`meshprovision.termsafe` (itself a pure standard-library leaf), so
every other module in the crypto group (and beyond) can depend on it
without risking an import cycle.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import MutableMapping
from typing import Any, Final

from meshprovision.termsafe import terminal_safe

__all__ = [
    "REDACTED",
    "REDACTION_DIGEST_CHARS",
    "SAFE_KEY_NAMES",
    "SENSITIVE_KEY_NAMES",
    "SENSITIVE_KEY_SUFFIXES",
    "SecretBytes",
    "fingerprint",
    "library_record_may_leak",
    "redact",
    "redact_processor",
    "reveal",
    "scrub_text",
]

REDACTED: Final[str] = "<redacted>"
"""Placeholder text substituted for scrubbed key-shaped substrings."""

REDACTION_DIGEST_CHARS: Final[int] = 8
"""Default number of hex digest characters kept in a fingerprint label."""

SENSITIVE_KEY_NAMES: Final[frozenset[str]] = frozenset(
    {
        "private_key",
        "privatekey",
        "privkey",
        "priv",
        "private",
        "public_key",
        "publickey",
        "pubkey",
        "key",
        "keys",
        "key_material",
        "material",
        "psk",
        "channel_psk",
        "secret",
        "password",
        "passphrase",
        "passwd",
        "token",
        "admin_key",
        "adminkey",
        "ble_pin",
        "fixed_pin",
        "pin",
        "session_key",
    }
)
"""Log-event/mapping key names (after normalization) treated as secret."""

SENSITIVE_KEY_SUFFIXES: Final[tuple[str, ...]] = (
    "_key",
    "_psk",
    "_secret",
    "_password",
    "_token",
    "_pin",
)
"""Key-name suffixes (after normalization) treated as secret."""

SAFE_KEY_NAMES: Final[frozenset[str]] = frozenset(
    {
        "key_ref",
        "key_refs",
        "key_type",
        "key_id",
        "fingerprint",
        "public_key_fingerprint",
        "keys_sheet",
    }
)
"""Key names that always win over :data:`SENSITIVE_KEY_NAMES`/suffixes.

These name metadata *about* a key (a sheet reference, a redacted digest,
an enum tag) rather than the key material itself, so they are exempt even
though they resemble a sensitive name.
"""

_B64_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])"
)
"""Matches a canonical base64 encoding of 32 raw bytes (44 chars, one '=')."""

_HEX_KEY_RE: Final[re.Pattern[str]] = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
"""Matches a 64-hex-digit encoding of 32 raw bytes.

``REDACTION_DIGEST_CHARS`` defaults to 8, so this project's own
``sha256:xxxxxxxx`` fingerprint labels are far too short to ever match
this pattern -- they are never eaten by their own scrubber.
"""

_LIBRARY_BYTES_LITERAL_RE: Final[re.Pattern[str]] = re.compile(r"""b['"]""")
"""Matches the start of a Python ``bytes`` literal, e.g. the ``b'...'``/
``b"..."`` a raw frame's ``repr()`` produces (``meshtastic.stream_interface``'s
``f"sending header:{header!r} b:{b!r}"``)."""

_LIBRARY_ESCAPED_QUOTE_RE: Final[re.Pattern[str]] = re.compile(
    r'"[^"\n]*\\(?:[0-7]{3}|x[0-9A-Fa-f]{2})'
)
"""Matches a protobuf text-format quoted string containing a C-style octal
or hex byte escape, e.g. ``private_key: "\\320Z\\300..."`` -- how the
installed ``meshtastic`` library's own ``str(FromRadio(...))``/
``str(ToRadio(...))`` renders non-printable key bytes."""

_LIBRARY_SECRET_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:private_key|privateKey|admin_key|adminKey|psk|fixed_pin|fixedPin|"
    r"session_passkey|sessionPasskey)\b"
)
"""Matches a secret protobuf field name, snake_case or camelCase, as it
appears in protobuf text format (``field_name: value``) regardless of
whether the value itself needed an escape -- e.g. a private key made
entirely of printable ASCII bytes renders with no octal escape at all."""


class SecretBytes:
    """An immutable wrapper whose repr/str/format never reveal its bytes.

    Every place in this project that holds raw key material in memory
    wraps it in a :class:`SecretBytes` as soon as it is produced or
    decoded, so that an accidental ``print()``, f-string, or log call
    prints a redacted fingerprint instead of the secret itself.

    Deliberately *not* defined: ``__bytes__``, ``__iter__``,
    ``__getitem__``, and any ``__bool__``-driven shortcut that would let
    generic code coerce an instance back into raw bytes without going
    through :meth:`reveal` explicitly.
    """

    __slots__ = ("_fingerprint", "_raw")

    def __init__(self, raw: bytes | bytearray) -> None:
        """Wrap ``raw`` as secret material.

        Args:
            raw: The bytes to wrap. Copied internally, so later mutation
                of a ``bytearray`` passed in does not affect the wrapper.

        Raises:
            TypeError: If ``raw`` is not ``bytes`` or ``bytearray``.
        """
        if not isinstance(raw, bytes | bytearray):
            raise TypeError(f"SecretBytes requires bytes or bytearray, got {type(raw).__name__}")
        self._raw: bytes = bytes(raw)
        self._fingerprint: str | None = None

    @property
    def fingerprint(self) -> str:
        """A stable, non-reversible label for the wrapped bytes.

        Returns:
            For example ``"sha256:ab12cd34"``. Computed once and cached.
        """
        if self._fingerprint is None:
            self._fingerprint = fingerprint(self._raw)
        return self._fingerprint

    def reveal(self) -> bytes:
        """Return the wrapped raw bytes. The only way out of this wrapper.

        Returns:
            The raw secret bytes.
        """
        return self._raw

    def reveal_b64(self) -> str:
        """Return the base64 encoding of the wrapped raw bytes.

        This returns secret material as a string. Never log or print the
        result; only pass it to a destination that is itself trusted with
        the secret (a config write, an encrypted store, ...).

        Unlike :func:`meshprovision.crypto.keys.encode_key`, this does
        not validate that the wrapped material is exactly
        ``X25519_KEY_SIZE`` bytes -- :mod:`meshprovision.crypto.keys`
        imports :class:`SecretBytes` from this module, so delegating
        here would be circular. Every current caller only ever wraps a
        32-byte X25519 key, but that is an invariant held by convention
        across call sites, not enforced by this method itself.

        Returns:
            The base64-encoded secret.
        """
        return base64.b64encode(self._raw).decode("ascii")

    def __len__(self) -> int:
        """Return the length, in bytes, of the wrapped material.

        Returns:
            ``len(self.reveal())``.
        """
        return len(self._raw)

    def __eq__(self, other: object) -> bool:
        """Compare in constant time against another :class:`SecretBytes`.

        Args:
            other: The value to compare against.

        Returns:
            ``True`` if both wrap byte-equal secrets. ``NotImplemented``
            if ``other`` is not a :class:`SecretBytes`.
        """
        if not isinstance(other, SecretBytes):
            return NotImplemented
        return hmac.compare_digest(self._raw, other._raw)

    def __hash__(self) -> int:
        """Return a hash derived from the full sha256 digest, not the raw bytes.

        Returns:
            A hash safe to use in sets/dict keys without ever materializing
            the raw bytes in a traceback of a hash collision, etc.
        """
        return hash(hashlib.sha256(self._raw).digest())

    def __repr__(self) -> str:
        """Return a redacted representation.

        Returns:
            For example ``"<redacted:sha256:ab12cd34>"``.
        """
        return f"<redacted:{self.fingerprint}>"

    def __str__(self) -> str:
        """Return a redacted representation, same as :meth:`__repr__`.

        Returns:
            For example ``"<redacted:sha256:ab12cd34>"``.
        """
        return self.__repr__()

    def __format__(self, spec: str) -> str:
        """Return a redacted representation regardless of ``spec``.

        This closes the classic f-string leak (``f"{secret:>40}"`` would
        otherwise happily pad and print raw material).

        Args:
            spec: The format spec. Ignored.

        Returns:
            The same text as :meth:`__repr__`.
        """
        del spec
        return self.__repr__()


def fingerprint(
    material: bytes | bytearray | str | SecretBytes, *, chars: int = REDACTION_DIGEST_CHARS
) -> str:
    """Return a stable, non-reversible label for a secret value.

    Args:
        material: The value to fingerprint. A ``str`` is encoded as
            UTF-8 first; a :class:`SecretBytes` is unwrapped via
            :meth:`SecretBytes.reveal`.
        chars: Number of hex digest characters to keep, clamped to
            ``[1, 64]``.

    Returns:
        For example ``"sha256:ab12cd34"``.

    Raises:
        TypeError: If ``material`` is not one of the accepted types.
    """
    clamped_chars = max(1, min(64, chars))
    if isinstance(material, SecretBytes):
        raw = material.reveal()
    elif isinstance(material, str):
        raw = material.encode("utf-8")
    elif isinstance(material, bytes | bytearray):
        raw = bytes(material)
    else:
        raise TypeError(
            f"fingerprint() expects bytes, str, or SecretBytes, got {type(material).__name__}"
        )
    digest = hashlib.sha256(raw).hexdigest()
    return f"sha256:{digest[:clamped_chars]}"


def redact(value: bytes | bytearray | str | SecretBytes) -> str:
    """Return a redacted, fingerprinted representation of ``value``.

    Args:
        value: The secret value to redact.

    Returns:
        For example ``"<redacted:sha256:ab12cd34>"``.
    """
    return f"<redacted:{fingerprint(value)}>"


def reveal(value: bytes | SecretBytes) -> bytes:
    """Return the raw bytes of either a ``bytes`` object or a :class:`SecretBytes`.

    Args:
        value: The value to unwrap.

    Returns:
        The raw bytes.

    Raises:
        TypeError: If ``value`` is neither ``bytes`` nor :class:`SecretBytes`.
    """
    if isinstance(value, SecretBytes):
        return value.reveal()
    if isinstance(value, bytes):
        return value
    raise TypeError(f"reveal() expects bytes or SecretBytes, got {type(value).__name__}")


def scrub_text(text: str) -> str:
    """Replace anything shaped like raw 32-byte key material with a placeholder.

    Applies two patterns, in order: a canonical base64 encoding of 32
    bytes, then a 64-hex-digit encoding of 32 bytes. This is a defense-in
    depth net for free-text log messages and exception strings that might
    accidentally interpolate a key -- it complements, rather than
    replaces, routing secrets through :class:`SecretBytes` in the first
    place.

    Args:
        text: The text to scrub.

    Returns:
        ``text`` with every key-shaped substring replaced by
        :data:`REDACTED`.
    """
    scrubbed = _B64_KEY_RE.sub(REDACTED, text)
    return _HEX_KEY_RE.sub(REDACTED, scrubbed)


def library_record_may_leak(message: str) -> bool:
    r"""Decide whether a third-party (``meshtastic``) log message may carry secret bytes.

    ``scrub_text`` only catches base64/hex *encodings* of a 32-byte key.
    The installed ``meshtastic`` library instead logs raw protobuf
    messages via their default ``str()``/``repr()``, which renders
    non-printable bytes as C-style octal/hex escapes inside a quoted
    field (``private_key: "\320Z..."``), or dumps a raw serialized frame
    as a Python ``bytes`` literal (``b'...'``) -- neither shape is caught
    by ``scrub_text``. This is a coarse, message-shape predicate meant to
    be paired with withholding the whole message, not a scrubber: it
    deliberately over-matches (e.g. any admin response containing a
    ``payload:`` field) rather than risk missing a real leak.

    Args:
        message: The already-interpolated log message
            (``logging.LogRecord.getMessage()``), not the raw format
            string.

    Returns:
        ``True`` if the message contains a Python bytes-literal prefix,
        a protobuf text-format escaped byte string, a secret field name
        (``private_key``, ``admin_key``, ``psk``, ``fixed_pin``,
        ``session_passkey``, in snake_case or camelCase), or a
        ``payload:`` field (which can carry a serialized ``AdminMessage``
        including a pushed private key).
    """
    return bool(
        _LIBRARY_BYTES_LITERAL_RE.search(message)
        or _LIBRARY_ESCAPED_QUOTE_RE.search(message)
        or _LIBRARY_SECRET_FIELD_RE.search(message)
        or "payload:" in message
    )


def _normalize_key_name(name: str) -> str:
    """Canonicalize a mapping-key name for sensitivity classification.

    Args:
        name: The raw key name.

    Returns:
        The lower-cased, stripped form used for set membership checks.
    """
    return name.strip().lower()


def _is_sensitive_key(name: str) -> bool:
    """Decide whether a log-event/mapping key name denotes secret material.

    Args:
        name: The key name to classify.

    Returns:
        ``True`` if the (normalized) name is sensitive. Membership in
        :data:`SAFE_KEY_NAMES` always overrides a positive match.
    """
    normalized = _normalize_key_name(name)
    if normalized in SAFE_KEY_NAMES:
        return False
    if normalized in SENSITIVE_KEY_NAMES:
        return True
    return any(normalized.endswith(suffix) for suffix in SENSITIVE_KEY_SUFFIXES)


def _redact_event_value(value: object) -> object:
    """Redact one log-event value known to sit under a sensitive key name.

    Args:
        value: The value to redact.

    Returns:
        :func:`redact` of ``value`` when it is ``bytes``, ``bytearray``,
        or :class:`SecretBytes` -- real key material with enough entropy
        that a truncated SHA-256 fingerprint does not meaningfully expose
        it. :data:`REDACTED` for everything else, including ``str``: a
        short string under a sensitive key (a 6-digit BLE PIN, a weak
        password) does not have enough entropy for a hash to hide it --
        the fingerprint alone is cheaply brute-forceable -- so it gets no
        fingerprint at all, not even a redacted one.
    """
    if isinstance(value, bytes | bytearray | SecretBytes):
        return redact(value)
    return REDACTED


def redact_processor(
    logger: object, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """A structlog processor that scrubs secrets from one log event.

    Must be installed as the last processor before the renderer (see the
    module docstring), so every other processor has already run.

    Args:
        logger: The bound logger instance. Unused; required by the
            structlog processor signature.
        method_name: The name of the log method invoked (``"info"``,
            ``"warning"``, ...). Unused; required by the structlog
            processor signature.
        event_dict: The event's key/value pairs.

    Returns:
        A **new** mapping: every value under a sensitive key name is
        replaced per :func:`_redact_event_value` (a fingerprinted
        :func:`redact` for ``bytes``/``bytearray``/:class:`SecretBytes`,
        :data:`REDACTED` for everything else), every :class:`SecretBytes`
        value is replaced by :func:`redact` regardless of its key name,
        and every remaining string value is passed through
        :func:`scrub_text` and then
        :func:`~meshprovision.termsafe.terminal_safe` (multi-line log
        events are expected, so newlines are kept). The input mapping is
        never mutated.
    """
    del logger, method_name
    scrubbed: dict[str, Any] = {}
    for key, value in event_dict.items():
        if _is_sensitive_key(key):
            scrubbed[key] = _redact_event_value(value)
        elif isinstance(value, SecretBytes):
            scrubbed[key] = redact(value)
        elif isinstance(value, str):
            scrubbed[key] = terminal_safe(scrub_text(value), allow_newlines=True)
        else:
            scrubbed[key] = value
    return scrubbed
