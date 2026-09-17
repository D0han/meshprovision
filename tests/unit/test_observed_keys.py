"""Unit tests for :mod:`meshprovision.provisioning.observed_keys`."""

from __future__ import annotations

import pytest

from meshprovision.crypto.keys import KeyPair
from meshprovision.db import schema
from meshprovision.provisioning import observed_keys

pytestmark = pytest.mark.unit


def test_observed_owner_is_deterministic(keypair: KeyPair) -> None:
    """The same material always derives the same synthetic owner."""
    # Arrange / Act
    first = observed_keys.observed_owner(keypair.public)
    second = observed_keys.observed_owner(keypair.public)

    # Assert
    assert first == second


def test_observed_owner_differs_for_different_material(keypair_factory) -> None:  # type: ignore[no-untyped-def]
    """Two distinct keys derive two distinct synthetic owners."""
    # Arrange
    a = keypair_factory()
    b = keypair_factory()

    # Act / Assert
    assert observed_keys.observed_owner(a.public) != observed_keys.observed_owner(b.public)


def test_observed_owner_starts_with_reserved_prefix(keypair: KeyPair) -> None:
    """The synthetic owner is always tagged with the reserved prefix."""
    # Act
    owner = observed_keys.observed_owner(keypair.public)

    # Assert
    assert owner.startswith(observed_keys.OBSERVED_PREFIX)


def test_observed_owner_matches_ref_pattern(keypair: KeyPair) -> None:
    """A minted owner is a valid owner_node_id/key_ref shape."""
    # Act
    owner = observed_keys.observed_owner(keypair.public)

    # Assert
    assert schema.REF_PATTERN.match(owner)


def test_observed_owner_never_ends_in_a_key_suffix(keypair: KeyPair) -> None:
    """A minted owner never collides with the _pub/_priv/_psk suffix rule."""
    # Act
    owner = observed_keys.observed_owner(keypair.public)

    # Assert
    assert not owner.endswith(("_pub", "_priv", "_psk"))


def test_observed_key_ref_appends_pub_suffix(keypair: KeyPair) -> None:
    """The public-key ref is the owner with _pub appended."""
    # Act
    owner = observed_keys.observed_owner(keypair.public)
    ref = observed_keys.observed_key_ref(keypair.public)

    # Assert
    assert ref == f"{owner}_pub"


def test_observed_key_ref_widens_with_more_chars(keypair: KeyPair) -> None:
    """A wider digest produces a longer, still-prefixed ref."""
    # Act
    narrow = observed_keys.observed_key_ref(keypair.public)
    wide = observed_keys.observed_key_ref(keypair.public, chars=16)

    # Assert
    assert wide != narrow
    assert wide.startswith(observed_keys.OBSERVED_PREFIX)
    assert len(wide) > len(narrow)


def test_is_observed_owner_true_for_minted_owner(keypair: KeyPair) -> None:
    """is_observed_owner recognizes a value this module minted."""
    # Act
    owner = observed_keys.observed_owner(keypair.public)

    # Assert
    assert observed_keys.is_observed_owner(owner)


@pytest.mark.parametrize("owner", ["deadbe01", "ADMIN1", "observed", "observedX"])
def test_is_observed_owner_false_for_non_observed_values(owner: str) -> None:
    """is_observed_owner rejects node ids, template refs, and near-misses."""
    # Act / Assert
    assert not observed_keys.is_observed_owner(owner)


def test_is_observed_ref_true_for_minted_public_ref(keypair: KeyPair) -> None:
    """is_observed_ref recognizes a full key_ref this module minted."""
    # Act
    ref = observed_keys.observed_key_ref(keypair.public)

    # Assert
    assert observed_keys.is_observed_ref(ref)


@pytest.mark.parametrize(
    "ref", ["deadbe01_pub", "deadbe01_priv", "ADMIN1_pub", "deadbe01_psk", "observedX_pub"]
)
def test_is_observed_ref_false_for_ordinary_refs(ref: str) -> None:
    """is_observed_ref rejects ordinary node/admin refs and near-misses."""
    # Act / Assert
    assert not observed_keys.is_observed_ref(ref)


def test_is_observed_ref_true_without_a_known_suffix(keypair: KeyPair) -> None:
    """is_observed_ref still recognizes a bare observed owner with no suffix."""
    # Act
    owner = observed_keys.observed_owner(keypair.public)

    # Assert
    assert observed_keys.is_observed_ref(owner)
