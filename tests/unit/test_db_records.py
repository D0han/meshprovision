"""Tests for meshprovision.db.nodes and meshprovision.db.keys."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.config.template import BASE36_ALPHABET, PatternSpec
from meshprovision.crypto import redact
from meshprovision.db import schema
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository, find_next_free_name
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType, ManagementMode
from meshprovision.errors import (
    AdminRefUnresolvedError,
    DbIntegrityError,
    EnumMappingError,
    KeyNotFoundError,
    NamespaceExhaustedError,
    NodeNotFoundError,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# NodeRecord.
# ---------------------------------------------------------------------------


def test_node_record_round_trip_full(keypair) -> None:
    record = NodeRecord(
        node_id="deadbe01",
        short_name="MT00",
        long_name="Meshtastic MT00",
        hw_model="RAK4631",
        main_chipset="nRF52840",
        firmware_type="vanilla",
        firmware_version="2.7.11",
        gps_lat=1.0,
        gps_lon=2.0,
        gps_alt=3,
        first_added_ts=datetime(2026, 1, 1, tzinfo=UTC),
        last_updated_ts=datetime(2026, 2, 1, tzinfo=UTC),
        authorized_admin_keys=("A_pub",),
        notes="hi",
        role="CLIENT",
        region="EU_868",
        ble_pin="012345",
        unregistered_admin_key_fingerprints=("sha256:aaaaaaaa", "sha256:bbbbbbbb"),
    )
    assert NodeRecord.from_row(record.to_row()) == record


def test_from_row_missing_management_defaults_to_template() -> None:
    row = NodeRecord(node_id="deadbe01").to_row()
    del row["management"]
    assert NodeRecord.from_row(row).management is ManagementMode.TEMPLATE

    row["management"] = ""
    assert NodeRecord.from_row(row).management is ManagementMode.TEMPLATE


def test_from_row_empty_role_region_stays_empty_for_an_observed_row() -> None:
    """Regression test: an OBSERVED row's blank role/region must round-trip blank.

    Defaulting an empty cell to CLIENT/EU_868 on every reload would
    silently re-fabricate the exact "never guess" state
    provisioning.adopt.adopted_record() takes care not to write in the
    first place.
    """
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED, role="", region="")
    row = record.to_row()
    assert row["role"] == ""
    assert row["region"] == ""

    reloaded = NodeRecord.from_row(row)
    assert reloaded.role == ""
    assert reloaded.region == ""


def test_from_row_empty_role_region_defaults_for_a_template_row() -> None:
    """A TEMPLATE row's blank role/region cell still safety-nets to defaults.

    build_plan always resolves a real value, so an empty cell here is
    anomalous, unlike the OBSERVED case above.
    """
    row = NodeRecord(node_id="deadbe01").to_row()
    row["role"] = ""
    row["region"] = ""

    reloaded = NodeRecord.from_row(row)
    assert reloaded.role == "CLIENT"
    assert reloaded.region == "EU_868"


def test_to_row_always_recomputes_derived_columns() -> None:
    record = NodeRecord(node_id="deadbe01", hw_model="RAK4631")
    stale = record.with_updates(main_chipset="totally wrong")
    row = stale.to_row()
    assert row["main_chipset"] == "nRF52840"
    assert row["private_key_ref"] == "deadbe01_priv"
    assert row["public_key_ref"] == "deadbe01_pub"
    assert row["channel_psk_ref"] == "deadbe01_psk"


@pytest.mark.parametrize(
    "raw",
    ["deadbe01", "!deadbe01", "0xDEADBE01", "3735928321"],
)
def test_node_id_normalization_from_every_form(raw: str) -> None:
    record = NodeRecord(node_id=raw)
    assert record.node_id == "deadbe01"


def test_role_region_hw_model_canonicalisation_and_error() -> None:
    record = NodeRecord(node_id="deadbe01", role="client", region="eu_868", hw_model="rak4631")
    assert record.role == "CLIENT"
    assert record.region == "EU_868"
    assert record.hw_model == "RAK4631"

    with pytest.raises(EnumMappingError):
        NodeRecord(node_id="deadbe01", role="NOT_A_ROLE")


def test_ble_pin_five_digits_raises_without_leaking_digits() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        NodeRecord(node_id="deadbe01", ble_pin="12345")
    messages = [err["msg"] for err in exc_info.value.errors()]
    assert all("12345" not in msg for msg in messages)


def test_touched_sets_first_added_only_when_unset() -> None:
    record = NodeRecord(node_id="deadbe01")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    touched_once = record.touched(now=now)
    assert touched_once.first_added_ts == now
    assert touched_once.last_updated_ts == now

    later = datetime(2026, 2, 1, tzinfo=UTC)
    touched_twice = touched_once.touched(now=later)
    assert touched_twice.first_added_ts == now
    assert touched_twice.last_updated_ts == later


def test_with_updates_revalidates_and_never_mutates() -> None:
    record = NodeRecord(node_id="deadbe01", short_name="MT00")
    updated = record.with_updates(short_name="MT01")
    assert updated.short_name == "MT01"
    assert record.short_name == "MT00"
    assert updated is not record


# ---------------------------------------------------------------------------
# KeyRecord.
# ---------------------------------------------------------------------------


def test_key_record_key_value_canonicalised(keypair) -> None:
    record = KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, keypair.public)
    assert record.key_value.get_secret_value() == keypair.public_b64


def test_key_record_inconsistent_key_ref_raises() -> None:
    with pytest.raises(DbIntegrityError):
        KeyRecord(
            key_ref="wrong_ref",
            owner_node_id="deadbe01",
            key_type=KeyType.ADMIN_PUBLIC,
            key_value="A" * 43 + "=",
        )


def test_key_record_repr_shows_only_ref_and_fingerprint(keypair) -> None:
    record = KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, keypair.public)
    text = repr(record)
    assert "deadbe01_pub" in text
    assert "sha256:" in text
    assert keypair.public_b64 not in text


def test_key_record_material_secret_fingerprint(keypair) -> None:
    record = KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, keypair.public)
    assert record.material() == keypair.public
    assert record.secret().reveal() == keypair.public
    assert record.fingerprint.startswith("sha256:")


def test_for_keypair_produces_pub_priv_pair(keypair) -> None:
    pub, priv = KeyRecord.for_keypair("deadbe01", keypair)
    assert pub.key_ref == "deadbe01_pub"
    assert priv.key_ref == "deadbe01_priv"
    assert pub.material() == keypair.public
    assert priv.material() == keypair.private.reveal()


# ---------------------------------------------------------------------------
# Repositories over one shared OdsDatabase.
# ---------------------------------------------------------------------------


@pytest.fixture
def db(empty_ods: Path) -> OdsDatabase:
    session = OdsDatabase(empty_ods)
    session.load()
    return session


@pytest.fixture
def nodes(db: OdsDatabase) -> NodeRepository:
    return NodeRepository(db)


@pytest.fixture
def keys(db: OdsDatabase) -> KeyRepository:
    return KeyRepository(db)


def test_node_repo_upsert_find_get_exists_delete(nodes: NodeRepository, db: OdsDatabase) -> None:
    record = NodeRecord(node_id="deadbe01", short_name="MT00")
    nodes.upsert(record)
    db.save()

    assert nodes.exists("deadbe01") is True
    found = nodes.find("deadbe01")
    assert found is not None
    assert found.short_name == "MT00"
    fetched = nodes.get("deadbe01")
    assert fetched.short_name == "MT00"

    assert nodes.delete("deadbe01") is True
    db.save()
    assert nodes.exists("deadbe01") is False
    assert nodes.delete("deadbe01") is False


def test_node_repo_get_missing_raises(nodes: NodeRepository) -> None:
    with pytest.raises(NodeNotFoundError):
        nodes.get("deadbe01")


def test_key_repo_get_missing_raises(keys: KeyRepository) -> None:
    with pytest.raises(KeyNotFoundError):
        keys.get("deadbe01_pub")


def test_resolve_admin_refs_unknown_ref_hint_mentions_both_bootstrap_commands(
    keys: KeyRepository,
) -> None:
    with pytest.raises(AdminRefUnresolvedError) as exc_info:
        keys.resolve_admin_refs(["ADMIN1"])
    hint = exc_info.value.hint or ""
    assert "mesh admin bootstrap" in hint
    assert "mesh admin import" in hint


def test_admin_key_bytes_ordering(keys: KeyRepository, keypair_factory, db: OdsDatabase) -> None:
    kp1 = keypair_factory()
    kp2 = keypair_factory()
    pub1, _ = KeyRecord.for_keypair("ADMIN1", kp1)
    pub2, _ = KeyRecord.for_keypair("ADMIN2", kp2)
    keys.upsert(pub1)
    keys.upsert(pub2)
    db.save()

    result = keys.admin_key_bytes(["ADMIN2", "ADMIN1"])
    assert result == (kp2.public, kp1.public)


def test_public_key_map(keys: KeyRepository, keypair_factory, db: OdsDatabase) -> None:
    kp = keypair_factory()
    pub, priv = KeyRecord.for_keypair("deadbe01", kp)
    keys.upsert(pub)
    keys.upsert(priv)
    db.save()
    key_map = keys.public_key_map()
    assert key_map == {"deadbe01_pub": kp.public}


def test_has_private(keys: KeyRepository, keypair, db: OdsDatabase) -> None:
    assert keys.has_private("ADMIN1") is False
    _, priv = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(priv)
    db.save()
    assert keys.has_private("ADMIN1") is True


def test_has_private_rejects_a_private_key_that_does_not_match_its_public(
    keys: KeyRepository, keypair_factory, db: OdsDatabase
) -> None:
    kp_a, kp_b = keypair_factory(), keypair_factory()
    pub, _ = KeyRecord.for_keypair("ADMIN1", kp_a)
    _, priv = KeyRecord.for_keypair("ADMIN1", kp_b)
    keys.upsert(pub)
    keys.upsert(priv)
    db.save()
    assert keys.has_private("ADMIN1") is False
    assert keys.private_key_mismatch("ADMIN1") is True


def test_has_private_accepts_a_matching_pair(keys: KeyRepository, keypair, db: OdsDatabase) -> None:
    pub, priv = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    keys.upsert(priv)
    db.save()
    assert keys.has_private("ADMIN1") is True
    assert keys.private_key_mismatch("ADMIN1") is False


def test_has_private_tolerates_malformed_private_material(
    keys: KeyRepository, keypair, db: OdsDatabase
) -> None:
    pub, _ = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    db.replace(
        schema.KEYS_SHEET,
        [
            *db.rows(schema.KEYS_SHEET),
            {
                "key_ref": "ADMIN1_priv",
                "owner_node_id": "ADMIN1",
                "key_type": "admin_private",
                "key_value": "not-valid-base64!!!",
                "created_ts": "",
            },
        ],
    )
    assert keys.has_private("ADMIN1") is False


def test_private_key_mismatch_is_false_when_no_private_row_exists(
    keys: KeyRepository, keypair, db: OdsDatabase
) -> None:
    pub, _ = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    db.save()
    assert keys.has_private("ADMIN1") is False
    assert keys.private_key_mismatch("ADMIN1") is False


def test_keypair_for(keys: KeyRepository, keypair, db: OdsDatabase) -> None:
    material_absent = keys.keypair_for("deadbe01")
    assert material_absent.public is None
    assert material_absent.private is None
    assert material_absent.fingerprint() is None

    pub, priv = KeyRecord.for_keypair("deadbe01", keypair)
    keys.upsert(pub)
    keys.upsert(priv)
    db.save()

    material = keys.keypair_for("deadbe01")
    assert material.public == keypair.public
    assert material.private is not None
    assert material.private.reveal() == keypair.private.reveal()
    assert material.fingerprint() is not None


def test_keypair_for_private_only_falls_back_from_public(
    keys: KeyRepository, keypair, db: OdsDatabase
) -> None:
    """fingerprint() falls back to the private key when only it is present."""
    _pub, priv = KeyRecord.for_keypair("deadbe02", keypair)
    keys.upsert(priv)
    db.save()

    material = keys.keypair_for("deadbe02")
    assert material.public is None
    assert material.private is not None
    fingerprint = material.fingerprint()
    assert fingerprint is not None
    assert fingerprint == redact.fingerprint(keypair.private)


def test_unresolved_admin_refs(
    nodes: NodeRepository, keys: KeyRepository, db: OdsDatabase, keypair
) -> None:
    record = NodeRecord(node_id="deadbe01", authorized_admin_keys=("ADMIN1_pub", "ADMIN2_pub"))
    nodes.upsert(record)
    pub, _ = KeyRecord.for_keypair("ADMIN1", keypair)
    keys.upsert(pub)
    db.save()

    unresolved = nodes.unresolved_admin_refs(keys)
    assert unresolved == {"deadbe01": ("ADMIN2_pub",)}


# ---------------------------------------------------------------------------
# find_next_free_name.
# ---------------------------------------------------------------------------


def test_find_next_free_name_skips_used_case_insensitively() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    used = {"mt00", "MT01"}
    index, name = find_next_free_name(spec, used)
    assert name == "MT02"
    assert index == 2


def test_find_next_free_name_honours_start() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    index, name = find_next_free_name(spec, set(), start=5)
    assert index == 5
    assert name == "MT05"


def test_find_next_free_name_raises_when_full() -> None:
    spec = PatternSpec.compile("MT{n}", "AB", field="short_name_pattern")
    used = {spec.render(0), spec.render(1)}
    with pytest.raises(NamespaceExhaustedError):
        find_next_free_name(spec, used)


def test_next_free_name_selects_by_field_name(nodes: NodeRepository, db: OdsDatabase) -> None:
    long_spec = PatternSpec.compile(
        "Meshtastic MT{n}{n}", BASE36_ALPHABET, field="long_name_pattern"
    )
    short_spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")

    record = NodeRecord(node_id="deadbe01", short_name="MT00", long_name="Meshtastic MT00")
    nodes.upsert(record)
    db.save()

    _, long_name = nodes.next_free_name(long_spec, is_long=True)
    assert long_name != "Meshtastic MT00"
    _, short_name = nodes.next_free_name(short_spec, is_long=False)
    assert short_name != "MT00"
