"""Tests for meshprovision.crypto.keys.

Covers ``public_key_matches`` and ``clamp`` (both were exported via
``__all__`` with zero direct test coverage before this file existed;
``public_key_matches`` is wired into ``_evaluate_lockdown``, a gate that
decides whether a device is irreversibly locked, so these tests pin its
behavior against unmodified source), the ``decode_key``/``encode_key``
validation surface that turns database rows, CLI input, and weak-key
blocklist entries into validated key bytes, and ``KeyPair``'s length
invariants, ``fingerprint``, and ``__repr__``.
"""

from __future__ import annotations

import base64

import pytest

from meshprovision.crypto.keys import (
    B64_KEY_PREFIX,
    X25519_KEY_SIZE,
    KeyPair,
    clamp,
    decode_key,
    encode_key,
    is_clamped,
    public_key_matches,
)
from meshprovision.crypto.redact import SecretBytes
from meshprovision.errors import KeyMaterialError

pytestmark = pytest.mark.unit

_VALID_B64 = encode_key(bytes(range(X25519_KEY_SIZE)))
_TOO_LONG_B64 = base64.b64encode(bytes(64)).decode("ascii")


def test_public_key_matches_accepts_a_derived_pair(keypair_factory) -> None:
    kp = keypair_factory()
    assert public_key_matches(kp.private, kp.public) is True


def test_public_key_matches_rejects_an_unrelated_public_key(keypair_factory) -> None:
    kp_a, kp_b = keypair_factory(), keypair_factory()
    assert public_key_matches(kp_a.private, kp_b.public) is False


def test_public_key_matches_raises_on_a_wrong_length_public_key(keypair_factory) -> None:
    kp = keypair_factory()
    with pytest.raises(KeyMaterialError) as excinfo:
        public_key_matches(kp.private, kp.public[:31])
    assert excinfo.value.reason == "invalid public key length"


def test_public_key_matches_raises_on_a_wrong_length_private_key() -> None:
    with pytest.raises(KeyMaterialError) as excinfo:
        public_key_matches(b"\x01" * 31, b"\x02" * 32)
    assert excinfo.value.reason == "invalid private key length"


def test_clamp_produces_a_clamped_scalar_that_derives_the_same_public_key(
    keypair_factory,
) -> None:
    kp = keypair_factory()
    clamped = clamp(kp.private)
    assert is_clamped(clamped) is True
    assert clamp(clamped) == clamped


def test_clamp_exact_output_bytes_on_genuinely_unclamped_input() -> None:
    """Pin clamp()'s exact byte output against fixed, known-unclamped input.

    A freshly generated keypair's private key is already clamped on this
    environment's backend (OpenSSL-family), so a test that only checks
    ``is_clamped(clamp(x))`` against real keys can pass even if the
    masking logic is completely broken -- it never actually exercises
    clamp() against anything requiring a real bit change.
    """
    all_ones = bytes([0xFF] * X25519_KEY_SIZE)
    assert is_clamped(all_ones) is False
    clamped = clamp(all_ones)
    assert clamped == bytes([0xF8]) + bytes([0xFF] * 30) + bytes([0x7F])
    assert is_clamped(clamped) is True

    all_zeros = bytes(X25519_KEY_SIZE)
    assert is_clamped(all_zeros) is False
    clamped_zeros = clamp(all_zeros)
    assert clamped_zeros == bytes(31) + bytes([0x40])
    assert is_clamped(clamped_zeros) is True


def test_is_clamped_requires_all_three_conditions_independently() -> None:
    """Each RFC 7748 clamping condition is independently necessary.

    Guards the ``and``/``or`` boundary between the three clauses: every
    negative case here keeps two of the three conditions satisfied, so a
    connector accidentally weakened to ``or`` would wrongly report the
    scalar as clamped.
    """
    baseline = bytearray(X25519_KEY_SIZE)
    baseline[0] = 0x00  # low 3 bits clear
    baseline[31] = 0x40  # top bit clear, second-highest bit set
    assert is_clamped(bytes(baseline)) is True

    bad_low_bits = bytearray(baseline)
    bad_low_bits[0] = 0x07  # violates "low 3 bits clear" only
    assert is_clamped(bytes(bad_low_bits)) is False

    bad_top_bit = bytearray(baseline)
    bad_top_bit[31] = 0xC0  # violates "top bit clear" only (bit 6 stays set)
    assert is_clamped(bytes(bad_top_bit)) is False

    bad_second_bit = bytearray(baseline)
    bad_second_bit[31] = 0x00  # violates "second-highest bit set" only
    assert is_clamped(bytes(bad_second_bit)) is False


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        pytest.param(12345, "invalid type", id="not-a-string"),
        pytest.param(None, "invalid type", id="none"),
        pytest.param(b"\x00" * 32, "invalid type", id="raw-bytes-not-str"),
        pytest.param("", "empty value", id="empty"),
        pytest.param("   ", "empty value", id="whitespace-only"),
        pytest.param(B64_KEY_PREFIX, "empty value", id="prefix-with-nothing-after"),
        pytest.param("AAAA!!!!", "invalid base64 characters", id="bang"),
        pytest.param("AAAA AAAA", "invalid base64 characters", id="inner-space"),
        pytest.param("AAAA\nAAAA", "invalid base64 characters", id="inner-newline"),
        pytest.param("AAAA", "invalid decoded length", id="too-short"),
        pytest.param(_TOO_LONG_B64, "invalid decoded length", id="too-long"),
    ],
)
def test_decode_key_rejects(value, reason) -> None:
    with pytest.raises(KeyMaterialError) as excinfo:
        decode_key(value)  # type: ignore[arg-type]
    assert excinfo.value.reason == reason


def test_decode_key_rejects_malformed_base64() -> None:
    with pytest.raises(KeyMaterialError) as excinfo:
        decode_key("AAAAA", field="private_key")
    assert "private_key is not valid base64" in str(excinfo.value)


def test_decode_key_rejects_a_non_canonical_encoding_of_a_valid_key() -> None:
    # The final data character carries 2 key bits in its high bits and 4
    # stray bits that must be zero; flipping the low bits produces a
    # second, non-canonical base64 string for the same 32 bytes.
    raw = bytes(range(X25519_KEY_SIZE))
    canonical = encode_key(raw)
    non_canonical = canonical[:42] + "9" + "="

    assert non_canonical != canonical
    assert base64.b64decode(non_canonical, validate=True) == raw

    with pytest.raises(KeyMaterialError) as excinfo:
        decode_key(non_canonical)
    assert excinfo.value.reason == "non-canonical base64 encoding"


def test_decode_key_accepts_a_canonical_key_with_and_without_the_prefix() -> None:
    raw = bytes(range(X25519_KEY_SIZE))
    canonical = encode_key(raw)
    assert decode_key(canonical) == raw
    assert decode_key(B64_KEY_PREFIX + canonical) == raw
    assert decode_key(f"  {canonical}\n") == raw


def test_decode_key_errors_name_the_field_and_never_the_value() -> None:
    secret_looking = "notavalidkeybutlooksbase64ish"  # noqa: S105 -- not a password, a decode_key input fixture
    with pytest.raises(KeyMaterialError) as excinfo:
        decode_key(secret_looking, field="admin_private_key")
    rendered = str(excinfo.value)
    assert "admin_private_key" in rendered
    assert secret_looking not in rendered


def test_encode_key_rejects_a_non_bytes_value() -> None:
    with pytest.raises(KeyMaterialError) as excinfo:
        encode_key("not bytes")  # type: ignore[arg-type]
    assert excinfo.value.reason == "invalid type"


def test_encode_key_rejects_a_wrong_length_value() -> None:
    with pytest.raises(KeyMaterialError) as excinfo:
        encode_key(b"\x01" * 31)
    assert excinfo.value.reason == "invalid key length"
    assert excinfo.value.expected_length == X25519_KEY_SIZE
    assert excinfo.value.actual_length == 31


def test_encode_key_decode_key_round_trip(keypair_factory) -> None:
    kp = keypair_factory()
    assert decode_key(encode_key(kp.public)) == kp.public


def test_keypair_rejects_a_wrong_length_public_key(keypair_factory) -> None:
    kp = keypair_factory()
    with pytest.raises(KeyMaterialError) as excinfo:
        KeyPair(private=kp.private, public=kp.public[:31])
    assert excinfo.value.reason == "invalid public key length"


def test_keypair_rejects_a_wrong_length_private_key(keypair_factory) -> None:
    kp = keypair_factory()
    with pytest.raises(KeyMaterialError) as excinfo:
        KeyPair(private=SecretBytes(b"\x01" * 31), public=kp.public)
    assert excinfo.value.reason == "invalid private key length"


def test_keypair_repr_and_fingerprint_never_expose_the_private_key(
    keypair_factory,
) -> None:
    kp = keypair_factory()
    rendered = repr(kp)
    assert kp.private_b64() not in rendered
    assert kp.public_b64 in rendered
    assert kp.fingerprint.startswith("sha256:")
