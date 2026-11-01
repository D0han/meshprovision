"""Tests for meshprovision.provisioning.persist (the ODS write gate; no real device)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.renumber import renumber_note
from meshprovision.db.schema import KeyOrigin, ManagementMode
from meshprovision.errors import AtomicWriteError, ExitCode, RenumberRefusedError
from meshprovision.nodeid import key_derived_id
from meshprovision.provisioning import detect
from meshprovision.provisioning.apply import apply_plan
from meshprovision.provisioning.apply_session import (
    ApplyOutcome,
    InPlaceSession,
    WriteResult,
    WriteStatus,
)
from meshprovision.provisioning.persist import persist_result
from meshprovision.provisioning.plan import PlanInputs, build_plan
from tests.unit.apply_fakes import FakeIfaceForApply, fake_node_id, minimal_template
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit


def test_persist_result_refuses_on_uncertain_outcome(tmp_path) -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(
        node_id=fake_node_id(), results=(bad_result,), dry_run=False, record=None
    )

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    mtime_before = db_path.stat().st_mtime_ns
    persisted = persist_result(outcome, nodes=nodes, keys=keys, origin=KeyOrigin.CAPTURED)
    assert persisted is False
    assert db_path.stat().st_mtime_ns == mtime_before
    assert nodes.exists("deadbe01") is False


def test_persist_result_refuses_when_may_update_database_is_false_with_a_record_present(
    tmp_path,
) -> None:
    """The gate's two halves (may_update_database, record presence) are independent.

    ApplyOutcome is a plain public dataclass; nothing stops constructing
    one with may_update_database=False (here via dry_run=True) alongside
    a non-None record, even though apply_plan itself never produces that
    combination. persist_result's own docstring frames it as "the single
    gate", so the may_update_database half must refuse on its own,
    independent of whether record happens to be present.
    """
    outcome = ApplyOutcome(
        node_id=fake_node_id(),
        results=(),
        dry_run=True,
        verified=False,
        record=NodeRecord(node_id="deadbe01"),
    )
    assert outcome.record is not None
    assert outcome.may_update_database is False

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    persisted = persist_result(outcome, nodes=nodes, keys=keys, origin=KeyOrigin.CAPTURED)
    assert persisted is False
    assert nodes.exists("deadbe01") is False


def _confirmed_outcome(make_live) -> tuple[ApplyOutcome, KeyPair]:
    template = minimal_template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    session = InPlaceSession(FakeIfaceForApply())  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)
    assert outcome.ok is True, outcome.describe()
    assert outcome.record is not None
    return outcome, kp


def test_persist_result_reports_divergence_when_the_save_fails(
    tmp_path, make_live, monkeypatch
) -> None:
    outcome, kp = _confirmed_outcome(make_live)

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AtomicWriteError("disk went away", path=str(db_path))

    monkeypatch.setattr(db, "save", _boom)
    mtime_before = db_path.stat().st_mtime_ns
    with pytest.raises(AtomicWriteError) as excinfo:
        persist_result(outcome, nodes=nodes, keys=keys, keypair=kp, origin=KeyOrigin.CAPTURED)

    assert "written and verified on the device" in excinfo.value.message
    assert "could not be saved" in excinfo.value.message
    assert "disagree" in excinfo.value.message
    assert "disk went away" in excinfo.value.message
    assert "deadbe01" in excinfo.value.message
    assert excinfo.value.__cause__ is not None
    assert excinfo.value.exit_code == ExitCode.DB
    assert "--force-regenerate-key" not in excinfo.value.user_message
    assert "The device's own keypair was not recorded either" in excinfo.value.user_message
    assert db_path.stat().st_mtime_ns == mtime_before


def test_persist_result_converts_a_bare_oserror_from_the_save(
    tmp_path, make_live, monkeypatch
) -> None:
    outcome, kp = _confirmed_outcome(make_live)

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    def _boom(*args: object, **kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(db, "save", _boom)
    with pytest.raises(AtomicWriteError) as excinfo:
        persist_result(outcome, nodes=nodes, keys=keys, keypair=kp, origin=KeyOrigin.CAPTURED)

    assert "written and verified on the device" in excinfo.value.message
    assert "disagree" in excinfo.value.message
    assert "No space left on device" in excinfo.value.message
    assert isinstance(excinfo.value.__cause__, OSError)
    assert excinfo.value.exit_code == ExitCode.DB


def test_persist_result_omits_the_keypair_hint_when_no_key_was_generated(
    tmp_path, make_live, monkeypatch
) -> None:
    outcome, _ = _confirmed_outcome(make_live)

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AtomicWriteError("disk went away", path=str(db_path))

    monkeypatch.setattr(db, "save", _boom)
    with pytest.raises(AtomicWriteError) as excinfo:
        persist_result(outcome, nodes=nodes, keys=keys, keypair=None, origin=KeyOrigin.CAPTURED)

    assert "--force-regenerate-key" not in excinfo.value.user_message
    assert "re-run `mesh provision`" in excinfo.value.user_message
    assert "--enroll" not in excinfo.value.user_message


_SAVE_FAILURE_HINT_BASE = (
    "Fix the write problem (free space, permissions) and re-run `mesh provision` for "
    "this node: the next run re-reads the device's live configuration and rewrites the row."
)
_PENDING_RECOVERY = (
    "The node's new keypair was not recorded either, but it is still in this node's "
    "pending-keypair file: the next `mesh provision` recovers it automatically, without "
    "writing a new key to the device."
)
_FOREIGN_CONFIRMATION = (
    "That run sees the node as FOREIGN (not in the database) and asks for confirmation: "
    "answer yes, or pass --yes on a non-interactive run."
)


def _failed_save_hint(
    tmp_path,
    make_live,
    monkeypatch,
    *,
    origin: KeyOrigin,
    keypair: bool = True,
    prior_management: ManagementMode | None = None,
    prior_key: bool = False,
) -> tuple[str, KeyRepository]:
    """Run persist_result into a failing save; return the hint and the session's keys."""
    outcome, kp = _confirmed_outcome(make_live)
    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)
    if prior_management is not None:
        nodes.upsert(NodeRecord(node_id="deadbe01", management=prior_management))
    if prior_key:
        for record in KeyRecord.for_keypair("deadbe01", generate_keypair(), origin=origin):
            keys.upsert(record)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AtomicWriteError("disk went away", path=str(db_path))

    monkeypatch.setattr(db, "save", _boom)
    with pytest.raises(AtomicWriteError) as excinfo:
        persist_result(
            outcome,
            nodes=nodes,
            keys=keys,
            keypair=kp if keypair else None,
            origin=origin,
        )
    assert excinfo.value.hint is not None
    return excinfo.value.hint, keys


@pytest.mark.parametrize(
    ("origin", "prior_management", "prior_key", "expected"),
    [
        pytest.param(
            KeyOrigin.GENERATED,
            None,
            False,
            f"{_PENDING_RECOVERY} If that file is lost, the next run instead records the "
            f"device's current key as captured. {_FOREIGN_CONFIRMATION}",
            id="generated-first-provision",
        ),
        pytest.param(
            KeyOrigin.GENERATED,
            ManagementMode.TEMPLATE,
            True,
            f"{_PENDING_RECOVERY} If that file is lost, the next run instead reports the "
            "device's key as differing from the Keys sheet and adopts it -- expected here.",
            id="generated-recorded-node",
        ),
        pytest.param(
            KeyOrigin.GENERATED,
            ManagementMode.TEMPLATE,
            False,
            f"{_PENDING_RECOVERY} If that file is lost, the next run instead records the "
            "device's current key as captured.",
            id="generated-row-without-a-key",
        ),
        pytest.param(
            KeyOrigin.CAPTURED,
            None,
            False,
            "The device's own keypair was not recorded either; the next `mesh provision` "
            f"captures it again. {_FOREIGN_CONFIRMATION}",
            id="captured-first-capture",
        ),
        pytest.param(
            KeyOrigin.CAPTURED,
            ManagementMode.TEMPLATE,
            True,
            "The device's keypair was not recorded either; the next `mesh provision` "
            "reports it as differing from the Keys sheet again and adopts it -- expected here.",
            id="captured-recorded-node",
        ),
    ],
)
def test_persist_result_save_failure_hint_says_how_the_next_run_records_the_keypair(
    tmp_path, make_live, monkeypatch, origin, prior_management, prior_key, expected
) -> None:
    hint, _ = _failed_save_hint(
        tmp_path,
        make_live,
        monkeypatch,
        origin=origin,
        prior_management=prior_management,
        prior_key=prior_key,
    )

    assert hint == f"{_SAVE_FAILURE_HINT_BASE} {expected}"
    assert "--force-regenerate-key" not in hint


def test_persist_result_save_failure_hint_reads_the_prior_key_before_this_runs_upsert(
    tmp_path, make_live, monkeypatch
) -> None:
    """A first provision has no prior public key, though its own upsert just added one.

    The hint must come from the state *before* this run: reading the
    ``Keys`` sheet after the upsert would always find the key, and turn
    a first provision's "recorded as captured" fallback into a bogus
    "reported as differing".
    """
    hint, keys = _failed_save_hint(tmp_path, make_live, monkeypatch, origin=KeyOrigin.GENERATED)

    assert keys.find("deadbe01_pub") is not None
    assert "records the device's current key as captured" in hint
    assert "differing" not in hint
    assert _FOREIGN_CONFIRMATION in hint


@pytest.mark.parametrize(
    ("prior_management", "asks_for_enroll"),
    [
        pytest.param(ManagementMode.OBSERVED, True, id="observed-row"),
        pytest.param(ManagementMode.TEMPLATE, False, id="template-row"),
        pytest.param(None, False, id="no-row"),
    ],
)
def test_persist_result_save_failure_hint_asks_for_enroll_only_for_an_observed_row(
    tmp_path, make_live, monkeypatch, prior_management, asks_for_enroll
) -> None:
    hint, _ = _failed_save_hint(
        tmp_path,
        make_live,
        monkeypatch,
        origin=KeyOrigin.CAPTURED,
        keypair=False,
        prior_management=prior_management,
    )

    enroll = (
        "Because that row was never saved, the node is still marked observed -- "
        "pass --enroll again on the re-run."
    )
    assert (hint == f"{_SAVE_FAILURE_HINT_BASE} {enroll}") is asks_for_enroll
    assert (hint == _SAVE_FAILURE_HINT_BASE) is not asks_for_enroll


def _renumbered_outcome(kp: KeyPair, *, record: NodeRecord) -> ApplyOutcome:
    """A confirmed outcome after a proven renumber to ``kp``'s derived id."""
    new = key_derived_id(kp.public)
    return ApplyOutcome(
        node_id=new,
        results=(),
        dry_run=False,
        verified=True,
        record=record.with_updates(node_id=new.hex),
        previous_node_id=fake_node_id(),
    )


def _session(tmp_path) -> tuple[OdsDatabase, NodeRepository, KeyRepository]:
    db = OdsDatabase.create(tmp_path / "db.ods")
    return db, NodeRepository(db), KeyRepository(db)


_THEN = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def test_persist_result_moves_the_row_of_a_renumbered_node_to_its_new_id(tmp_path) -> None:
    old_kp, kp = generate_keypair(), generate_keypair()
    new = key_derived_id(kp.public)
    db, nodes, keys = _session(tmp_path)
    old = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE, notes="roof")
    nodes.upsert(old)
    for record in KeyRecord.for_keypair("deadbe01", old_kp, origin=KeyOrigin.GENERATED):
        keys.upsert(record)
    nodes.upsert(
        NodeRecord(
            node_id="cafe0003",
            management=ManagementMode.TEMPLATE,
            authorized_admin_keys=("deadbe01_pub",),
        )
    )
    db.save()

    persisted = persist_result(
        _renumbered_outcome(kp, record=old),
        nodes=nodes,
        keys=keys,
        keypair=kp,
        origin=KeyOrigin.GENERATED,
        now=_THEN,
    )

    assert persisted is True
    reloaded = OdsDatabase(tmp_path / "db.ods")
    reloaded.load()
    rows = NodeRepository(reloaded)
    assert rows.find("deadbe01") is None
    assert rows.get(new).notes == f"roof; {renumber_note(fake_node_id(), until=_THEN)}"
    assert rows.get("cafe0003").authorized_admin_keys == (f"{new.hex}_pub",)
    stored = KeyRepository(reloaded).keypair_for(new.hex)
    assert stored.public == kp.public
    assert KeyRepository(reloaded).find("deadbe01_pub") is None


def test_persist_result_records_a_renumbered_first_provisioning_with_the_note(tmp_path) -> None:
    kp = generate_keypair()
    new = key_derived_id(kp.public)
    _db, nodes, keys = _session(tmp_path)

    persisted = persist_result(
        _renumbered_outcome(kp, record=NodeRecord(node_id="deadbe01")),
        nodes=nodes,
        keys=keys,
        keypair=kp,
        origin=KeyOrigin.GENERATED,
        now=_THEN,
    )

    assert persisted is True
    assert [record.node_id for record in nodes.all()] == [new.hex]
    assert nodes.get(new).notes == renumber_note(fake_node_id(), until=_THEN)
    assert keys.keypair_for(new.hex).public == kp.public


@pytest.mark.parametrize("prior_row", [True, False], ids=["moved-row", "first-provisioning"])
def test_persist_result_refuses_a_renumber_onto_an_id_that_has_a_row(
    tmp_path, prior_row: bool
) -> None:
    kp = generate_keypair()
    new = key_derived_id(kp.public)
    db, nodes, keys = _session(tmp_path)
    if prior_row:
        nodes.upsert(NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE))
    nodes.upsert(NodeRecord(node_id=new.hex, short_name="ZZ99"))
    db.save()
    mtime_before = (tmp_path / "db.ods").stat().st_mtime_ns

    with pytest.raises(RenumberRefusedError, match="already has a row"):
        persist_result(
            _renumbered_outcome(kp, record=NodeRecord(node_id="deadbe01")),
            nodes=nodes,
            keys=keys,
            keypair=kp,
            origin=KeyOrigin.GENERATED,
        )

    assert (tmp_path / "db.ods").stat().st_mtime_ns == mtime_before


def test_persist_result_save_failure_after_a_renumber_says_where_the_node_went(
    tmp_path, monkeypatch
) -> None:
    kp = generate_keypair()
    new = key_derived_id(kp.public)
    db, nodes, keys = _session(tmp_path)

    def _boom(*args: object, **kwargs: object) -> None:
        raise AtomicWriteError("disk went away", path="x")

    monkeypatch.setattr(db, "save", _boom)

    with pytest.raises(AtomicWriteError) as excinfo:
        persist_result(
            _renumbered_outcome(kp, record=NodeRecord(node_id="deadbe01")),
            nodes=nodes,
            keys=keys,
            keypair=kp,
            origin=KeyOrigin.GENERATED,
        )

    assert f"The node now reports {new.display}" in excinfo.value.user_message
    assert "`mesh db renumber`" in excinfo.value.user_message


def test_persist_result_save_failure_after_a_renumber_hints_from_the_old_rows_history(
    tmp_path, monkeypatch
) -> None:
    """The row the node had (under its old id) is what the re-run finds, not a FOREIGN node."""
    kp = generate_keypair()
    db, nodes, keys = _session(tmp_path)
    old = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED)
    nodes.upsert(old)
    db.save()

    def _boom(*args: object, **kwargs: object) -> None:
        raise AtomicWriteError("disk went away", path="x")

    monkeypatch.setattr(db, "save", _boom)

    with pytest.raises(AtomicWriteError) as excinfo:
        persist_result(
            _renumbered_outcome(kp, record=old),
            nodes=nodes,
            keys=keys,
            keypair=kp,
            origin=KeyOrigin.GENERATED,
        )

    assert "sees the node as FOREIGN" not in excinfo.value.user_message
    assert "pass --enroll again on the re-run" in excinfo.value.user_message
