"""Tests for meshprovision.provisioning.persist (the ODS write gate; no real device)."""

from __future__ import annotations

import pytest

from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyOrigin, ManagementMode
from meshprovision.errors import AtomicWriteError, ExitCode
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
from tests.unit.conftest import make_security
from tests.unit.test_apply import _FakeIfaceForApply, _node_id, _template

pytestmark = pytest.mark.unit


def test_persist_result_refuses_on_uncertain_outcome(tmp_path) -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(node_id=_node_id(), results=(bad_result,), dry_run=False, record=None)

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
        node_id=_node_id(),
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
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    session = InPlaceSession(_FakeIfaceForApply())  # type: ignore[arg-type]
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
