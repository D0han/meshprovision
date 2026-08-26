"""X25519 key generation, encoding, and clamping utilities.

This is the only module in the project that generates or manipulates raw
X25519 scalars. Key generation uses ``cryptography``'s
``X25519PrivateKey.generate()`` -- exactly the mechanism the
CVE-2025-52464 advisory itself recommends (``openssl genpkey -algorithm
x25519``) -- and every function that would otherwise expose raw private
key bytes returns or accepts a :class:`~meshprovision.crypto.redact.SecretBytes`
instead.

No function in this module ever passes raw key bytes into an exception
message, a logging call, an f-string, or a ``__repr__``. Where a key must
be identified for a human, use ``meshprovision.crypto.redact.fingerprint``.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from meshprovision.crypto import redact
from meshprovision.crypto.redact import SecretBytes
from meshprovision.errors import KeyMaterialError

__all__ = [
    "B64_KEY_PREFIX",
    "X25519_KEY_SIZE",
    "KeyPair",
    "clamp",
    "decode_key",
    "encode_key",
    "generate_keypair",
    "is_clamped",
    "public_from_private",
    "public_key_matches",
]

X25519_KEY_SIZE: Final[int] = 32
"""Byte length of a raw X25519 public or private key."""

B64_KEY_PREFIX: Final[str] = "base64:"
"""The Meshtastic CLI export convention.

Accepted and stripped by :func:`decode_key` when present, but never
emitted by :func:`encode_key` -- this project's own encodings are always
bare base64.
"""

_B64_ALPHABET: Final[frozenset[str]] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


@dataclass(frozen=True, slots=True, repr=False)
class KeyPair:
    """An X25519 private/public key pair.

    Attributes:
        private: The private scalar, wrapped so it can never be logged
            or printed by accident.
        public: The raw 32-byte public key. Not secret -- this is what
            gets written to a device's ``security.adminKey`` and stored
            in the ``Keys`` sheet.
    """

    private: SecretBytes
    public: bytes

    def __post_init__(self) -> None:
        """Validate that both keys are exactly 32 bytes.

        Raises:
            KeyMaterialError: If ``private`` or ``public`` is not
                :data:`X25519_KEY_SIZE` bytes long.
        """
        if len(self.public) != X25519_KEY_SIZE:
            raise KeyMaterialError(
                f"KeyPair.public must be {X25519_KEY_SIZE} bytes",
                reason="invalid public key length",
                expected_length=X25519_KEY_SIZE,
                actual_length=len(self.public),
            )
        if len(self.private) != X25519_KEY_SIZE:
            raise KeyMaterialError(
                f"KeyPair.private must be {X25519_KEY_SIZE} bytes",
                reason="invalid private key length",
                expected_length=X25519_KEY_SIZE,
                actual_length=len(self.private),
            )

    @property
    def public_b64(self) -> str:
        """The public key, base64-encoded.

        Returns:
            The canonical base64 encoding of :attr:`public`.
        """
        return encode_key(self.public)

    @property
    def fingerprint(self) -> str:
        """A redacted, non-reversible label for the public key.

        Returns:
            For example ``"sha256:ab12cd34"``.
        """
        return redact.fingerprint(self.public)

    def private_b64(self) -> str:
        """Return the private key, base64-encoded.

        This is a method, not a property, to make the call site read as
        the deliberate act it is: this returns secret material. Never
        log or print the result.

        Returns:
            The base64 encoding of the private key.
        """
        return self.private.reveal_b64()

    def __repr__(self) -> str:
        """Return a representation that never exposes the private key.

        Returns:
            For example
            ``"KeyPair(public='AbCd...', private=<redacted:sha256:...>)"``.
        """
        return f"KeyPair(public={self.public_b64!r}, private={self.private!r})"


def generate_keypair() -> KeyPair:
    """Generate a fresh X25519 key pair.

    Returns:
        A new :class:`KeyPair` from a freshly generated private scalar.
    """
    private_key = x25519.X25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return KeyPair(private=SecretBytes(raw_private), public=raw_public)


def _coerce_private_bytes(private: bytes | SecretBytes) -> bytes:
    """Unwrap and length-validate a private-key argument.

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.

    Returns:
        The raw private key bytes.

    Raises:
        KeyMaterialError: If the resolved value is not exactly
            :data:`X25519_KEY_SIZE` bytes.
    """
    raw = redact.reveal(private) if isinstance(private, SecretBytes) else private
    if not isinstance(raw, bytes | bytearray) or len(raw) != X25519_KEY_SIZE:
        raise KeyMaterialError(
            f"private key must be exactly {X25519_KEY_SIZE} bytes",
            reason="invalid private key length",
            expected_length=X25519_KEY_SIZE,
            actual_length=len(raw) if isinstance(raw, bytes | bytearray) else None,
        )
    return bytes(raw)


def public_from_private(private: bytes | SecretBytes) -> bytes:
    """Derive the X25519 public key for a private scalar.

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.

    Returns:
        The raw 32-byte public key.

    Raises:
        KeyMaterialError: If ``private`` is not exactly
            :data:`X25519_KEY_SIZE` bytes.
    """
    raw = _coerce_private_bytes(private)
    private_key = x25519.X25519PrivateKey.from_private_bytes(raw)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def encode_key(raw: bytes) -> str:
    """Encode 32 raw key bytes as canonical base64.

    Args:
        raw: The raw key bytes to encode.

    Returns:
        The base64 encoding of ``raw``, with no :data:`B64_KEY_PREFIX`.

    Raises:
        KeyMaterialError: If ``raw`` is not exactly
            :data:`X25519_KEY_SIZE` bytes.
    """
    if not isinstance(raw, bytes | bytearray):
        raise KeyMaterialError("key material must be bytes", reason="invalid type")
    if len(raw) != X25519_KEY_SIZE:
        raise KeyMaterialError(
            f"key must be exactly {X25519_KEY_SIZE} bytes",
            reason="invalid key length",
            expected_length=X25519_KEY_SIZE,
            actual_length=len(raw),
        )
    return base64.b64encode(bytes(raw)).decode("ascii")


def decode_key(value: str, *, field: str = "key") -> bytes:
    """Decode a base64-encoded key, validating strictly.

    Strips surrounding whitespace and a leading :data:`B64_KEY_PREFIX`
    (case-sensitive), rejects any character outside the base64 alphabet,
    requires the decoded length to be exactly :data:`X25519_KEY_SIZE`
    bytes, and requires the input to be the *canonical* base64 encoding
    of those bytes (rejecting non-canonical padding or stray trailing
    bits, which would otherwise silently decode to a different key than
    the one displayed).

    Args:
        value: The candidate base64 string.
        field: Name of the field being decoded, used only to identify
            the offending input in error messages -- never the value
            itself.

    Returns:
        The decoded 32 raw key bytes.

    Raises:
        KeyMaterialError: If ``value`` is empty, contains characters
            outside the base64 alphabet, is not valid base64, does not
            decode to exactly :data:`X25519_KEY_SIZE` bytes, or is not
            the canonical encoding of its decoded bytes.
    """
    if not isinstance(value, str):
        raise KeyMaterialError(f"{field} must be a string", reason="invalid type")
    token = value.strip()
    if token.startswith(B64_KEY_PREFIX):
        token = token[len(B64_KEY_PREFIX) :]
    if not token:
        raise KeyMaterialError(f"{field} is empty", reason="empty value")
    if not set(token) <= _B64_ALPHABET:
        raise KeyMaterialError(
            f"{field} contains characters outside the base64 alphabet",
            reason="invalid base64 characters",
        )
    try:
        raw = base64.b64decode(token, validate=True)
    except binascii.Error as exc:
        raise KeyMaterialError(f"{field} is not valid base64", reason=str(exc)) from exc
    if len(raw) != X25519_KEY_SIZE:
        raise KeyMaterialError(
            f"{field} must decode to exactly {X25519_KEY_SIZE} bytes",
            reason="invalid decoded length",
            expected_length=X25519_KEY_SIZE,
            actual_length=len(raw),
        )
    if base64.b64encode(raw).decode("ascii") != token:
        raise KeyMaterialError(
            f"{field} is not canonically base64-encoded",
            reason="non-canonical base64 encoding",
            expected_length=X25519_KEY_SIZE,
            actual_length=len(raw),
        )
    return raw


def is_clamped(private: bytes | SecretBytes) -> bool:
    """Check whether a private scalar is X25519-clamped.

    Per RFC 7748: bit pattern ``raw[0] & 0b0000_0111 == 0`` (the low 3
    bits of the first byte are clear), ``raw[31] & 0b1000_0000 == 0``
    (the top bit of the last byte is clear), and
    ``raw[31] & 0b0100_0000 == 0b0100_0000`` (the second-highest bit of
    the last byte is set).

    An **unclamped** private key is completely normal: OpenSSL-family
    backends (and therefore ``cryptography``'s
    ``X25519PrivateKey.generate()`` on some versions) can store the raw
    random scalar and clamp it only at use time, so this check alone must
    never be treated as evidence of compromise. See
    :func:`meshprovision.crypto.weakkeys.audit_private_key`'s
    ``check_clamping`` parameter, which defaults to ``False`` for exactly
    this reason.

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.

    Returns:
        ``True`` if the scalar is clamped.

    Raises:
        KeyMaterialError: If ``private`` is not exactly
            :data:`X25519_KEY_SIZE` bytes.
    """
    raw = _coerce_private_bytes(private)
    return (
        raw[0] & 0b0000_0111 == 0
        and raw[31] & 0b1000_0000 == 0
        and raw[31] & 0b0100_0000 == 0b0100_0000
    )


def clamp(private: bytes | SecretBytes) -> bytes:
    """Return a clamped copy of a private scalar.

    Never mutates the input; always returns a new ``bytes`` object.

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.

    Returns:
        A new, clamped 32-byte private scalar.

    Raises:
        KeyMaterialError: If ``private`` is not exactly
            :data:`X25519_KEY_SIZE` bytes.
    """
    raw = _coerce_private_bytes(private)
    clamped = bytearray(raw)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    return bytes(clamped)


def public_key_matches(private: bytes | SecretBytes, public: bytes) -> bool:
    """Check whether ``public`` is the public key derived from ``private``.

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.
        public: The raw 32-byte public key to compare against.

    Returns:
        ``True`` if the two keys correspond, compared in constant time.

    Raises:
        KeyMaterialError: If ``private`` is not exactly
            :data:`X25519_KEY_SIZE` bytes, or ``public`` is not exactly
            :data:`X25519_KEY_SIZE` bytes.
    """
    derived = public_from_private(private)
    if not isinstance(public, bytes | bytearray) or len(public) != X25519_KEY_SIZE:
        raise KeyMaterialError(
            f"public key must be exactly {X25519_KEY_SIZE} bytes",
            reason="invalid public key length",
            expected_length=X25519_KEY_SIZE,
            actual_length=len(public) if isinstance(public, bytes | bytearray) else None,
        )
    return hmac.compare_digest(derived, bytes(public))
