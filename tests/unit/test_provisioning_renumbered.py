"""Tests for :mod:`meshprovision.provisioning.renumbered`: a renumbered node at connect time."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.pending_keys import PendingKeypair
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import NodeRenumberedError
from meshprovision.nodeid import NodeId, key_derived_id
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, build_plan
from meshprovision.provisioning.renumbered import (
    PENDING_KEY_EVIDENCE,
    SAME_KEY_EVIDENCE,
    UNSET_REGION,
    refuse_renumbered,
    region_first_refusal,
    renumber_command,
    renumbered_error,
    renumbered_pending,
    renumbered_row,
)
from tests.unit.apply_fakes import minimal_template
from tests.unit.conftest import make_security

if TYPE_CHECKING:
    from collections.abc import Callable

    from meshprovision.crypto.keys import KeyPair
    from meshprovision.provisioning.detect_types import LiveConfig

pytestmark = pytest.mark.unit

_OLD: Final = NodeId.from_hex("deadbe01")
_EARLIER: Final = datetime(2026, 1, 1, tzinfo=UTC)


def _live(
    make_live: Callable[..., LiveConfig], keypair: KeyPair | None, node: NodeId
) -> LiveConfig:
    security = make_security(keypair=keypair) if keypair is not None else make_security(empty=True)
    return make_live(minimal_template(), node_id=node.hex, security=security)


def _row(nodes: NodeRepository, node: str, **fields: object) -> None:
    nodes.upsert(NodeRecord(node_id=node, management=ManagementMode.TEMPLATE, **fields))


def _key(keys: KeyRepository, owner: str, public: bytes) -> None:
    keys.upsert(
        KeyRecord.from_material(owner, KeyType.ADMIN_PUBLIC, public, origin=KeyOrigin.GENERATED)
    )


def _pending(node: NodeId, keypair: KeyPair) -> PendingKeypair:
    return PendingKeypair(
        node_id=node,
        public=keypair.public,
        private=keypair.private,
        created_ts=_EARLIER,
        path=Path(f"/nonexistent/nodes_db.pending-{node.hex}.json"),
    )


def test_renumber_command_names_both_bare_ids() -> None:
    assert renumber_command(_OLD, NodeId(0x3A7C19E2)) == "mesh db renumber deadbe01 3a7c19e2"


def test_renumbered_error_says_who_it_is_and_hints_the_command() -> None:
    error = renumbered_error(_OLD, NodeId(0x3A7C19E2), evidence=SAME_KEY_EVIDENCE)

    assert error.message == (
        "This is !deadbe01 (same public key) now reporting !3a7c19e2: firmware >= 2.8 derives "
        "the node id from the key."
    )
    assert error.hint is not None
    assert error.hint.endswith("mesh db renumber deadbe01 3a7c19e2")
    assert (error.old, error.new) == ("!deadbe01", "!3a7c19e2")
    assert error.exit_code == 5


def test_the_row_holding_the_devices_key_under_its_old_id_is_found(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    _row(nodes, _OLD.hex, short_name="AB01")
    _key(keys, _OLD.hex, keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    record = renumbered_row(live, nodes=nodes, keys=keys)

    assert record is not None
    assert record.short_name == "AB01"
    with pytest.raises(NodeRenumberedError) as caught:
        refuse_renumbered(live, nodes=nodes, keys=keys)
    assert caught.value.old == _OLD.display
    assert caught.value.new == key_derived_id(keypair.public).display
    assert SAME_KEY_EVIDENCE in caught.value.message


def test_a_device_whose_id_is_not_derived_from_its_key_is_no_renumber(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    """Our key on another, non-derived id is a clone or a restore: other audits own it."""
    _row(nodes, _OLD.hex)
    _key(keys, _OLD.hex, keypair.public)
    live = _live(make_live, keypair, NodeId.from_hex("cafe0002"))

    assert renumbered_row(live, nodes=nodes, keys=keys) is None
    refuse_renumbered(live, nodes=nodes, keys=keys)


def test_a_device_without_a_key_is_no_renumber(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keys: KeyRepository
) -> None:
    _row(nodes, _OLD.hex)

    assert renumbered_row(live=_live(make_live, None, _OLD), nodes=nodes, keys=keys) is None


def test_a_key_two_node_rows_hold_names_no_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    for node in (_OLD.hex, "cafe0003"):
        _row(nodes, node)
        _key(keys, node, keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_row(live, nodes=nodes, keys=keys) is None


def test_an_admin_alias_holding_the_key_does_not_count_as_a_node_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    _row(nodes, _OLD.hex)
    _key(keys, _OLD.hex, keypair.public)
    _key(keys, "ADMIN1", keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    record = renumbered_row(live, nodes=nodes, keys=keys)

    assert record is not None
    assert record.node_id == _OLD.hex


def test_an_orphan_key_row_under_the_new_id_does_not_hide_the_old_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
) -> None:
    new = key_derived_id(keypair.public)
    _row(nodes, _OLD.hex)
    _key(keys, _OLD.hex, keypair.public)
    _key(keys, new.hex, keypair.public)

    record = renumbered_row(_live(make_live, keypair, new), nodes=nodes, keys=keys)

    assert record is not None
    assert record.node_id == _OLD.hex


@pytest.mark.parametrize("archived", [True, False], ids=["archived", "no-row"])
def test_a_key_whose_row_is_archived_or_missing_names_no_row(
    make_live: Callable[..., LiveConfig],
    nodes: NodeRepository,
    keys: KeyRepository,
    keypair: KeyPair,
    archived: bool,
) -> None:
    if archived:
        _row(nodes, _OLD.hex, archived_at=_EARLIER)
    _key(keys, _OLD.hex, keypair.public)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_row(live, nodes=nodes, keys=keys) is None


def test_no_pending_keypair_recovers_nothing(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    live = _live(make_live, keypair, key_derived_id(keypair.public))
    assert renumbered_pending(live, None, nodes=nodes) is None


def test_a_pending_keypair_of_an_id_without_a_row_is_recovered(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    pending = _pending(_OLD, keypair)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_pending(live, pending, nodes=nodes) is pending


def test_a_pending_keypair_the_device_id_does_not_derive_from_is_not_used(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    live = _live(make_live, keypair, NodeId.from_hex("cafe0002"))
    assert renumbered_pending(live, _pending(_OLD, keypair), nodes=nodes) is None


def test_a_pending_keypair_of_a_live_row_refuses_until_the_row_is_moved(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    _row(nodes, _OLD.hex)
    new = key_derived_id(keypair.public)

    with pytest.raises(NodeRenumberedError) as caught:
        renumbered_pending(_live(make_live, keypair, new), _pending(_OLD, keypair), nodes=nodes)

    assert PENDING_KEY_EVIDENCE in caught.value.message
    assert caught.value.hint is not None
    assert caught.value.hint.endswith(renumber_command(_OLD, new))


def test_a_pending_keypair_of_an_archived_row_is_not_used(
    make_live: Callable[..., LiveConfig], nodes: NodeRepository, keypair: KeyPair
) -> None:
    _row(nodes, _OLD.hex, archived_at=_EARLIER)
    live = _live(make_live, keypair, key_derived_id(keypair.public))

    assert renumbered_pending(live, _pending(_OLD, keypair), nodes=nodes) is None


def _region_plan(
    make_live: Callable[..., LiveConfig], *, region: str, firmware: str
) -> tuple[ChangePlan, LiveConfig]:
    template = minimal_template()
    live = make_live(
        template,
        security=make_security(empty=True),
        firmware_version=firmware,
        section_overrides={"lora": {"region": region}},
    )
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    return build_plan(inputs), live


def test_setting_the_first_region_on_firmware_2_8_is_refused_with_the_manual_step(
    make_live: Callable[..., LiveConfig],
) -> None:
    plan, live = _region_plan(make_live, region=UNSET_REGION, firmware="2.8.0.47db0e3")

    refusal = region_first_refusal(plan, live)

    assert refusal is not None
    assert refusal.field == "lora.region"
    assert refusal.message.startswith("!deadbe01 has no LoRa region yet, and firmware >= 2.8")
    assert refusal.hint == (
        "Set the LoRa region first (Meshtastic app, or `meshtastic --set lora.region EU_868`), "
        "reconnect, then run `mesh provision` again."
    )
    assert refusal.exit_code == 5


@pytest.mark.parametrize(
    ("region", "firmware"),
    [
        pytest.param(UNSET_REGION, "2.7.26", id="2.7"),
        pytest.param(UNSET_REGION, "", id="no-version"),
        pytest.param(UNSET_REGION, "custom-build", id="unparseable"),
        pytest.param("US", "2.8.0", id="region-already-set"),
        pytest.param("EU_868", "2.8.0", id="no-region-write"),
    ],
)
def test_other_plans_are_not_refused_for_the_region(
    make_live: Callable[..., LiveConfig], region: str, firmware: str
) -> None:
    plan, live = _region_plan(make_live, region=region, firmware=firmware)

    assert region_first_refusal(plan, live) is None


def test_a_plan_that_leaves_an_unset_region_alone_is_not_refused(
    make_live: Callable[..., LiveConfig],
) -> None:
    """The template always names a region, so only a plan cut down by hand writes none."""
    plan, live = _region_plan(make_live, region=UNSET_REGION, firmware="2.8.0")
    plan = dataclasses.replace(
        plan, sections=tuple(s for s in plan.sections if s.section != "lora")
    )

    assert region_first_refusal(plan, live) is None
