"""Unit tests for meshprovision.cli.provision's error reporting.

Covers the admin-key-rotation error finalizer and what
``_apply_and_persist`` tells the operator after an uncertain apply.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from types import SimpleNamespace

import pytest

from meshprovision.cli.provision import ProvisionOptions, _apply_and_persist
from meshprovision.cli.provision_keys import finalize_admin_key_rotation_error
from meshprovision.config.template import load_template_text
from meshprovision.errors import AdminKeyRotationRefusedError
from meshprovision.provisioning import apply, detect
from meshprovision.provisioning.apply_session import ApplyOutcome, WriteResult, WriteStatus
from meshprovision.provisioning.plan import (
    ChangePlan,
    FieldChange,
    PlanInputs,
    SectionChange,
    build_plan,
)
from tests.unit.conftest import live_config_from_template, make_security

pytestmark = pytest.mark.unit


def test_finalize_capture_reason_hint_names_cve_and_ref_flag(keypair) -> None:
    """A ``"capture"`` refusal's hint points at ``--ref`` and the CVE.

    Not the old ``"adopt"`` wording, which is false when nothing was ever
    recorded.
    """
    template = load_template_text("version: 1\n")
    live = live_config_from_template(template, security=make_security(keypair=keypair))
    exc = AdminKeyRotationRefusedError(
        "deadbe01 has no recorded key, and the key it reports is already registered as: "
        "ADMIN1_pub.",
        reason="capture",
        admin_refs=("ADMIN1_pub",),
    )

    finalized = finalize_admin_key_rotation_error(exc, live)

    assert finalized.hint is not None
    assert "sha256:" in finalized.hint
    assert "--ref" in finalized.hint
    assert "CVE-2025-52464" in finalized.hint
    assert "than the one recorded" not in finalized.hint
    assert finalized.reported_fingerprint is not None
    assert "sha256:" in finalized.reported_fingerprint


# ---------------------------------------------------------------------------
# _apply_and_persist: what an uncertain outcome says about the security section.
# ---------------------------------------------------------------------------

_MAY_BE_LOCKED = (
    "The security section was sent but not confirmed: is_managed may have been applied, "
    "so the node may now be locked to its admin keys."
)
_NOT_LOCKED = (
    "The security section was not written: the node was not locked, "
    "and its keys and admin keys are unchanged."
)


class _RecordingCtx:
    """Just the ``CliContext`` methods ``_apply_and_persist`` reports through."""

    def __init__(self) -> None:
        self.infos: list[str] = []
        self.errors: list[str] = []

    def info(self, message: str) -> None:
        self.infos.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def success(self, message: str) -> None:
        raise AssertionError(f"unexpected success: {message}")


def _lockdown_plan() -> tuple[ChangePlan, detect.LiveConfig]:
    """A FACTORY plan whose security section sets ``is_managed``."""
    template = load_template_text("version: 1\n")
    live = live_config_from_template(template, security=make_security(empty=True))
    plan = build_plan(
        PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    )
    security = SectionChange(
        section="security",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="security", field="is_managed", current=False, desired=True),),
    )
    return dataclasses.replace(plan, sections=(security,)), live


def _report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, results: tuple[WriteResult, ...], **kw: bool
) -> _RecordingCtx:
    """Run ``_apply_and_persist`` with ``apply_plan`` returning ``results``."""
    plan, live = _lockdown_plan()
    outcome = ApplyOutcome(node_id=plan.node_id, results=results, **kw)
    monkeypatch.setattr(apply, "apply_plan", lambda *_a, **_k: outcome)
    ctx = _RecordingCtx()
    db = SimpleNamespace(path=tmp_path / "nodes.ods", nodes=None, keys=None)
    _apply_and_persist(
        ctx,  # type: ignore[arg-type]
        db,  # type: ignore[arg-type]
        SimpleNamespace(),  # type: ignore[arg-type]
        change_plan=plan,
        keypair=None,
        live=live,
        opts=ProvisionOptions(),
    )
    return ctx


_COMMIT_FAILED = WriteResult(
    "<verify>", WriteStatus.FAILED, "Could not commit the settings transaction: boom"
)


def test_apply_and_persist_warns_is_managed_may_be_applied_when_security_was_sent_unconfirmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An in-place commit failure sent security but never confirmed it: the node may be locked."""
    ctx = _report(
        monkeypatch,
        tmp_path,
        (
            _COMMIT_FAILED,
            WriteResult("security", WriteStatus.UNCONFIRMED, "sent inside the settings ..."),
        ),
        security_attempted=True,
    )

    assert _MAY_BE_LOCKED in ctx.errors
    assert not any("was not written" in line for line in ctx.infos)


def test_apply_and_persist_omits_the_may_be_locked_warning_once_is_managed_is_confirmed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A confirmed ``is_managed`` was not "sent but not confirmed", even if another check failed."""
    ctx = _report(
        monkeypatch,
        tmp_path,
        (
            WriteResult("security", WriteStatus.CONFIRMED, "confirmed", field="is_managed"),
            WriteResult("lora", WriteStatus.UNCONFIRMED, "mismatch", field="hop_limit"),
        ),
        security_attempted=True,
    )

    assert _MAY_BE_LOCKED not in ctx.errors


def test_apply_and_persist_begin_failure_still_says_the_node_was_not_locked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed transaction begin never sent security: the existing reassurance still prints."""
    ctx = _report(
        monkeypatch,
        tmp_path,
        (
            WriteResult(
                "<verify>", WriteStatus.FAILED, "Could not begin a settings transaction: boom"
            ),
            WriteResult(
                "security",
                WriteStatus.SKIPPED,
                "not written: could not begin a settings transaction",
            ),
        ),
        security_attempted=False,
    )

    assert _NOT_LOCKED in ctx.infos
    assert _MAY_BE_LOCKED not in ctx.errors
    assert "Not written (stopped after the failure above): security" in ctx.errors
