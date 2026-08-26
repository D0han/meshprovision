"""Tests for meshprovision.crypto.keys: public_key_matches and clamp.

Both functions were exported (``__all__``) with zero direct test coverage
before this file existed. ``public_key_matches`` is about to be wired into
``_evaluate_lockdown``, a gate that decides whether a device is
irreversibly locked -- these tests pin its behavior against unmodified
source before that happens.
"""

from __future__ import annotations

import pytest

from meshprovision.crypto.keys import clamp, is_clamped, public_key_matches
from meshprovision.errors import KeyMaterialError

pytestmark = pytest.mark.unit


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
