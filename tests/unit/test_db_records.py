"""Tests for meshprovision.db.nodes and meshprovision.db.keys."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.config.template import BASE36_ALPHABET, PatternSpec
from meshprovision.crypto import redact
from meshprovision.crypto.keys import encode_key
from meshprovision.db import schema
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository, find_next_free_name
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import FirmwareType, KeyType, ManagementMode
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


def test_node_record_round_trip_full(keypair, keypair_factory) -> None:
    unregistered = (encode_key(keypair_factory().public), encode_key(keypair.public))
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
        unregistered_admin_keys=unregistered,
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


@pytest.mark.parametrize("firmware_type", [FirmwareType.LORANET, FirmwareType.OTHER])
def test_non_default_firmware_type_survives_a_row_round_trip(
    firmware_type: FirmwareType,
) -> None:
    """A non-default ``firmware_type`` must not be masked by the default.

    ``from_row`` reads ``row.get("firmware_type") or VANILLA``; every other
    fixture stores ``"vanilla"``, which is also the fallback, so a corrupted
    read would look identical to a correct one.
    """
    record = NodeRecord(node_id="deadbe01", firmware_type=firmware_type)
    row = record.to_row()
    assert row["firmware_type"] == firmware_type.value
    assert NodeRecord.from_row(row).firmware_type is firmware_type


def test_unregistered_admin_keys_dedupe_by_canonical_form(keypair) -> None:
    """Two spellings of one key collapse to a single element.

    ``decode_key`` accepts both the bare base64 and the ``base64:`` form,
    so de-duplicating on the raw input string would keep both. The app's
    own write path (``adopted_record``) dedupes by material first; this
    guards a hand-edited cell or a future direct constructor caller.
    """
    encoded = encode_key(keypair.public)
    record = NodeRecord(
        node_id="deadbe01",
        unregistered_admin_keys=(encoded, f"base64:{encoded}", encoded),
    )
    assert len(record.unregistered_admin_keys) == 1
    assert record.unregistered_admin_key_materials() == (keypair.public,)


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


def test_for_keypair_records_the_caller_supplied_created_ts(keypair) -> None:
    """Both halves of the pair must carry the caller's timestamp.

    Every other call site relies on the implicit ``None`` default, so a
    ``for_keypair``/``from_material`` that dropped the argument on the floor
    would go unnoticed -- while the real callers (provisioning.apply,
    cli.admin, cli.provision) all pass an explicit timestamp.
    """
    created = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    pub, priv = KeyRecord.for_keypair("deadbe01", keypair, created_ts=created)
    assert pub.created_ts == created
    assert priv.created_ts == created
    assert pub.to_row()["created_ts"] == "2026-03-04T05:06:07Z"
    assert priv.to_row()["created_ts"] == "2026-03-04T05:06:07Z"


def test_from_material_records_the_caller_supplied_created_ts(keypair) -> None:
    created = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
    record = KeyRecord.from_material(
        "deadbe01", KeyType.ADMIN_PUBLIC, keypair.public, created_ts=created
    )
    assert record.created_ts == created
    assert KeyRecord.from_row(record.to_row()).created_ts == created


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


def test_key_repo_upsert_find_delete(keys: KeyRepository, keypair, db: OdsDatabase) -> None:
    pub, _ = KeyRecord.for_keypair("deadbe01", keypair)
    keys.upsert(pub)
    db.save()

    found = keys.find("deadbe01_pub")
    assert found is not None
    assert found.material() == keypair.public

    assert keys.delete("deadbe01_pub") is True
    db.save()
    assert keys.find("deadbe01_pub") is None
    assert keys.delete("deadbe01_pub") is False


def test_key_repo_delete_missing_returns_false(keys: KeyRepository) -> None:
    assert keys.delete("deadbe01_pub") is False


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


def test_find_next_free_name_defaults_to_index_zero() -> None:
    """The default ``start=0`` must actually allocate index 0 when it is free.

    ``test_find_next_free_name_skips_used_case_insensitively`` has both index
    0 and 1 taken, so it would still pass if the default became ``1``.
    """
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    index, name = find_next_free_name(spec, {"MT01"})
    assert index == 0
    assert name == "MT00"


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


def test_archived_node_frees_its_name_for_reuse(nodes: NodeRepository, db: OdsDatabase) -> None:
    """An archived node's name must not be reserved forever.

    ``mesh db forget`` never deletes the row (audit history survives)
    and there is no unarchive command, so if used_short_names()/
    used_long_names() kept counting an archived node's name as "in
    use," that name's slot would be permanently unusable by any
    replacement device -- a real leak against the pattern's finite
    capacity every time a node is decommissioned.
    """
    long_spec = PatternSpec.compile(
        "Meshtastic MT{n}{n}", BASE36_ALPHABET, field="long_name_pattern"
    )
    short_spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")

    record = NodeRecord(
        node_id="deadbe01",
        short_name="MT00",
        long_name="Meshtastic MT00",
        archived_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    nodes.upsert(record)
    db.save()

    assert "MT00" not in nodes.used_short_names()
    assert "Meshtastic MT00" not in nodes.used_long_names()

    _, short_name = nodes.next_free_name(short_spec, is_long=False)
    assert short_name == "MT00"
    _, long_name = nodes.next_free_name(long_spec, is_long=True)
    assert long_name == "Meshtastic MT00"


def _fill_namespace(nodes: NodeRepository, spec: PatternSpec, count: int) -> None:
    """Occupy the first ``count`` names of ``spec``, one node per name."""
    for index in range(count):
        nodes.upsert(NodeRecord(node_id=f"deadbe0{index}", short_name=spec.render(index)))


def test_next_free_name_warns_near_exhaustion(
    nodes: NodeRepository, db: OdsDatabase, caplog: pytest.LogCaptureFixture
) -> None:
    """9 of 10 names used hits the default 0.9 warn threshold, and still allocates."""
    spec = PatternSpec.compile("MT{n}", "0123456789", field="short_name_pattern")
    _fill_namespace(nodes, spec, 9)
    db.save()

    with caplog.at_level(logging.WARNING, logger="meshprovision.db.nodes"):
        index, name = nodes.next_free_name(spec)

    assert (index, name) == (9, "MT9")
    messages = [record.getMessage() for record in caplog.records]
    assert any("9 of 10 names used" in message for message in messages)


def test_next_free_name_stays_quiet_below_the_threshold(
    nodes: NodeRepository, db: OdsDatabase, caplog: pytest.LogCaptureFixture
) -> None:
    spec = PatternSpec.compile("MT{n}", "0123456789", field="short_name_pattern")
    _fill_namespace(nodes, spec, 5)
    db.save()

    with caplog.at_level(logging.WARNING, logger="meshprovision.db.nodes"):
        index, name = nodes.next_free_name(spec)

    assert (index, name) == (5, "MT5")
    assert caplog.records == []


def test_next_free_name_honours_an_explicit_warn_at(
    nodes: NodeRepository, db: OdsDatabase, caplog: pytest.LogCaptureFixture
) -> None:
    """An explicit ``warn_at`` overrides the default threshold in both directions."""
    spec = PatternSpec.compile("MT{n}", "0123456789", field="short_name_pattern")
    _fill_namespace(nodes, spec, 5)
    db.save()

    with caplog.at_level(logging.WARNING, logger="meshprovision.db.nodes"):
        nodes.next_free_name(spec, warn_at=0.5)
    assert any("5 of 10 names used" in record.getMessage() for record in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="meshprovision.db.nodes"):
        nodes.next_free_name(spec, warn_at=0.99)
    assert caplog.records == []
