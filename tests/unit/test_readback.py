"""Tests for meshprovision.provisioning.readback (verify_plan; no real device)."""

from __future__ import annotations

import base64

import pytest

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.crypto.keys import encode_key, generate_keypair
from meshprovision.provisioning import detect
from meshprovision.provisioning import readback as readback_module
from meshprovision.provisioning.apply import WriteStatus
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, build_plan
from meshprovision.provisioning.readback import verify_plan
from tests.unit.conftest import adopt_device_key_plan, make_security

pytestmark = pytest.mark.unit


def _template() -> TemplateConfig:
    return load_template_text("version: 1\n")


def test_verify_plan_all_matching_confirmed(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)

    # Build a "live_after" identical to the plan's desired state.
    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    non_key_results = [r for r in results if r.field not in ("public_key", "admin_key")]
    assert all(r.status == WriteStatus.CONFIRMED for r in non_key_results)


def test_verify_plan_mismatch_unconfirmed_with_expected_actual(make_live) -> None:
    template = _template()
    template2 = template.model_copy(
        update={"device": template.device.model_copy(update={"role": "ROUTER"})}
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template2,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        section_overrides={"device": {"role": "CLIENT"}},
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    role_result = next(r for r in results if r.field == "role")
    assert role_result.status == WriteStatus.UNCONFIRMED
    assert role_result.expected == "ROUTER"
    assert role_result.actual == "CLIENT"


def test_verify_plan_is_unmessagable_confirmed(make_live) -> None:
    template = _template().model_copy(update={"is_unmessagable": True})
    live = make_live(template, is_unmessagable=None, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.name_change.is_unmessagable_changed is True

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        is_unmessagable=True,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    result = next(r for r in results if r.field == "is_unmessagable")
    assert result.status == WriteStatus.CONFIRMED


def test_verify_plan_is_unmessagable_unconfirmed(make_live) -> None:
    template = _template().model_copy(update={"is_unmessagable": True})
    live = make_live(template, is_unmessagable=None, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.name_change.is_unmessagable_changed is True

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        is_unmessagable=False,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    result = next(r for r in results if r.field == "is_unmessagable")
    assert result.status == WriteStatus.UNCONFIRMED
    assert result.expected == "True"
    assert result.actual == "False"


def _is_unmessagable_plan_and_stale_after(make_live) -> tuple[ChangePlan, detect.LiveConfig]:
    """Build a plan turning is_unmessagable on, plus a post-write state still showing it off.

    The stale state is what a ``--no-reconnect`` session re-reads: the real
    ``Node.setOwner()`` never updates the interface's cached user. The plan
    renames the node too, so all three owner fields go out in one write.
    """
    template = _template().model_copy(update={"is_unmessagable": True})
    live = make_live(template, is_unmessagable=False, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="MT01",
        desired_long_name="Meshtastic MT01",
    )
    plan = build_plan(inputs)
    assert plan.name_change.is_unmessagable_changed is True
    return plan, live


def test_verify_plan_is_unmessagable_mismatch_without_read_back_is_reported_not_read_back(
    make_live,
) -> None:
    """--no-reconnect: a stale is_unmessagable is "not read back", never UNCONFIRMED.

    Before, it was the one owner field that ignored ``read_back``, so every
    --no-reconnect run changing it ended UNCERTAIN and never recorded the node.
    """
    plan, stale_after = _is_unmessagable_plan_and_stale_after(make_live)

    results = verify_plan(plan, stale_after, keypair=None, read_back=False)

    result = next(r for r in results if r.field == "is_unmessagable")
    assert (result.status, result.message) == (
        WriteStatus.CONFIRMED,
        "written; not read back (--no-reconnect)",
    )
    assert (result.expected, result.actual) == (None, None)


def test_verify_plan_without_read_back_reports_every_owner_field_alike(make_live) -> None:
    """Names and is_unmessagable go out in one setOwner() write, so they verify alike."""
    plan, stale_after = _is_unmessagable_plan_and_stale_after(make_live)
    assert plan.name_change.short_changed and plan.name_change.long_changed

    results = verify_plan(plan, stale_after, keypair=None, read_back=False)

    owner = sorted((r.field, r.status, r.message) for r in results if r.section == "owner")
    assert owner == [
        (field, WriteStatus.CONFIRMED, "written; not read back (--no-reconnect)")
        for field in ("is_unmessagable", "long_name", "short_name")
    ]


def test_apply_reuses_plan_values_equal() -> None:
    from meshprovision.provisioning import plan as plan_mod
    from meshprovision.provisioning import readback as readback_mod

    assert readback_mod.values_equal is plan_mod.values_equal


def test_verify_plan_int_one_against_desired_true_is_unconfirmed(make_live) -> None:
    template = _template()
    live = make_live(
        template,
        section_overrides={"lora": {"tx_enabled": False}},
        security=make_security(empty=True),
    )
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    tx_change = next(c for s in plan.sections for c in s.changes if c.field == "tx_enabled")
    assert tx_change.desired is True

    # The device reports the int 1 rather than the bool True.
    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        section_overrides={"lora": {"tx_enabled": 1}},
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    tx_result = next(r for r in results if r.field == "tx_enabled")
    assert tx_result.status == WriteStatus.UNCONFIRMED


def test_verify_plan_default_channel_confirmed_against_live_default_channel(make_live) -> None:
    """default_channel must be read off live_after.default_channel, not the generic value() path.

    live.value()/LiveConfig.sections/module_sections deliberately exclude
    default_channel (it is backed by a structurally different container),
    so without the dedicated branch this would always read None and
    falsely report UNCONFIRMED even on a fully successful write.
    """
    template = _template()
    template2 = template.model_copy(
        update={
            "default_channel": template.default_channel.model_copy(
                update={"position_precision": 12}
            )
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    assert plan.section("default_channel") is not None

    live_after = make_live(
        template2,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    result = next(r for r in results if r.section == "default_channel")
    assert result.status == WriteStatus.CONFIRMED


def test_verify_plan_default_channel_mismatch_is_unconfirmed(make_live) -> None:
    template = _template()
    template2 = template.model_copy(
        update={
            "default_channel": template.default_channel.model_copy(
                update={"position_precision": 12}
            )
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    result = next(r for r in results if r.section == "default_channel")
    assert result.status == WriteStatus.UNCONFIRMED
    assert result.expected == "12"


def test_verify_key_material_nodedb_present_but_wrong_is_unconfirmed(make_live) -> None:
    """A present-but-mismatched NodeDB key must not satisfy the cross-check.

    _verify_key_material's dual check (LocalConfig AND NodeDB) exists
    specifically for firmware issue #7449: LocalConfig can say a key
    write succeeded while NodeDB still disagrees. LocalConfig matching
    alone must not be enough when NodeDB is available and reports a
    *different* key, not merely absent.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True
    kp = generate_keypair()
    wrong_kp = generate_keypair()

    # LocalConfig confirms the right key...
    live_after = make_live(template, security=make_security(keypair=kp))
    # ...but NodeDB reports a different one entirely.
    result = readback_module._verify_key_material(
        plan, live_after, keypair=kp, device_public_key=encode_key(wrong_kp.public)
    )

    assert result is not None
    assert result.status == WriteStatus.UNCONFIRMED


def test_verify_plan_secret_field_expected_actual_redacted(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        ble_pin="123456",
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
        section_overrides={"bluetooth": {}},
    )
    results = verify_plan(plan, live_after, keypair=None)
    pin_result = next((r for r in results if r.field == "fixed_pin"), None)
    assert pin_result is not None
    assert pin_result.status == WriteStatus.UNCONFIRMED
    assert pin_result.expected == "<redacted>"
    assert pin_result.actual == "<redacted>"


def test_verify_plan_security_scalar_field_confirmed_via_live_security(make_live) -> None:
    """A security scalar field write must confirm via LiveConfig.security, not .value().

    LiveConfig.sections/module_sections deliberately exclude "security",
    so the generic live_after.value(...) lookup always returns None for
    it -- verify_plan's security branch must read via
    getattr(live_after.security, field, None) instead, or a real
    is_managed/admin_channel_enabled/etc. write would always report
    UNCONFIRMED even after a fully successful write.
    """
    template = _template()
    live = make_live(template, security=make_security(admin_channel_enabled=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    admin_channel_change = next(
        c
        for section in plan.sections
        for c in section.changes
        if section.section == "security" and c.field == "admin_channel_enabled"
    )
    assert admin_channel_change.desired is False

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(admin_channel_enabled=False),
    )
    results = verify_plan(plan, live_after, keypair=None)
    result = next(
        r for r in results if r.section == "security" and r.field == "admin_channel_enabled"
    )
    assert result.status == WriteStatus.CONFIRMED


def test_verify_plan_serial_enabled_confirmed_via_live_security(make_live) -> None:
    """serial_enabled -- like admin_channel_enabled -- must confirm via LiveConfig.security.

    template.security.serial_enabled defaults to None ("leave the
    device alone") and no other test in this suite ever sets it to a
    concrete value, so this readback path had zero coverage before this
    test despite serial_enabled being a real, documented template
    field (see the matching plan.py test for the plan-build half).
    """
    template = _template()
    opinionated_template = template.model_copy(
        update={"security": template.security.model_copy(update={"serial_enabled": True})}
    )
    live = make_live(template, security=make_security(serial_enabled=False))
    inputs = PlanInputs(
        live=live, template=opinionated_template, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    serial_change = next(
        c
        for section in plan.sections
        for c in section.changes
        if section.section == "security" and c.field == "serial_enabled"
    )
    assert serial_change.desired is True

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(serial_enabled=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    result = next(r for r in results if r.section == "security" and r.field == "serial_enabled")
    assert result.status == WriteStatus.CONFIRMED


def test_verify_plan_only_long_name_changed_does_not_affect_short_name_result(
    make_live,
) -> None:
    """Verifying two independent name fields when only one of them actually changed.

    A device whose short_name already fit the pattern while long_name
    still needed rewriting. An unchanged short_name is not part of the
    plan at all (per verify_plan's short_changed/long_changed gate,
    Round 37 aspect 1 finding #2), so it must produce no result
    whatsoever -- not a trivially-CONFIRMED one -- and must not interfere
    with or get conflated with long_name's own, separately-computed
    result.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_long_name="Meshtastic Node One",
    )
    plan = build_plan(inputs)
    assert not plan.name_change.short_changed
    assert plan.name_change.long_changed

    live_after = make_live(
        template,
        short_name=plan.name_change.current_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)

    assert not any(r.field == "short_name" for r in results)
    long_result = next(r for r in results if r.field == "long_name")
    assert long_result.status == WriteStatus.CONFIRMED


def test_verify_plan_unchanged_names_not_verified_against_blank_readback(
    make_live,
) -> None:
    """An empty NameChange must never be verified, even against a blank read-back.

    _verify_name's own docstring says a name that was not part of the
    plan must return None ("nothing to verify") -- but verify_plan used
    to pass concrete desired_short_name/desired_long_name unconditionally
    regardless of whether the plan actually changed them. A post-reboot
    blank getMyUser() readback (the NodeDB user entry not having
    repopulated yet -- the same condition
    test_verify_plan_empty_name_readback_is_unconfirmed_not_truncated
    guards for a name the plan DID write) for a name the plan never
    touched was misreported UNCONFIRMED, dragging the whole run into
    UNCERTAIN and blocking the database update for every field, even
    ones that verified fine. See Round 37 aspect 1 finding #2.
    """
    template = _template()
    template2 = template.model_copy(
        update={"device": template.device.model_copy(update={"role": "ROUTER"})}
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    assert plan.name_change.is_empty

    live_after = make_live(
        template2,
        short_name="",
        long_name="",
        section_overrides={"device": {"role": "ROUTER"}},
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)

    assert not any(r.section == "owner" for r in results)
    role_result = next(r for r in results if r.field == "role")
    assert role_result.status == WriteStatus.CONFIRMED


def test_verify_plan_only_short_name_changed_skips_blank_long_name_readback(
    make_live,
) -> None:
    """A changed name must still be verified normally when the other name is untouched.

    The mirror image of
    test_verify_plan_unchanged_names_not_verified_against_blank_readback:
    here short_name genuinely changed, so a blank readback for it is a
    real problem and must still surface as UNCONFIRMED. long_name did
    not change, so it must produce no result at all, even though its own
    readback is also blank.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="AB12",
    )
    plan = build_plan(inputs)
    assert plan.name_change.short_changed
    assert not plan.name_change.long_changed

    live_after = make_live(
        template,
        short_name="",
        long_name="",
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)

    name_results = [r for r in results if r.section == "owner"]
    assert [r.field for r in name_results] == ["short_name"]
    assert name_results[0].status == WriteStatus.UNCONFIRMED


def test_verify_plan_name_mismatch_with_read_back_false_is_confirmed_not_unconfirmed(
    make_live,
) -> None:
    """--no-reconnect (``read_back=False``) downgrades a name mismatch to CONFIRMED.

    Same setup as
    test_verify_plan_only_short_name_changed_skips_blank_long_name_readback,
    which asserts UNCONFIRMED for this exact mismatch under the default
    ``read_back=True`` -- here, with ``read_back=False``, the mismatch
    must instead report CONFIRMED with a note that the write could not be
    read back, since the in-memory interface a non-reconnecting session
    re-reads may simply not reflect the same post-write state a real
    reconnect would (see _verify_name).
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="AB12",
    )
    plan = build_plan(inputs)
    assert plan.name_change.short_changed

    live_after = make_live(
        template,
        short_name="",
        long_name="",
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None, read_back=False)

    name_results = [r for r in results if r.section == "owner"]
    assert [r.field for r in name_results] == ["short_name"]
    assert name_results[0].status == WriteStatus.CONFIRMED
    assert name_results[0].message == "written; not read back (--no-reconnect)"


def test_verify_plan_name_truncated_confirmed(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="ABCDE",
    )
    plan = build_plan(inputs)
    live_after = make_live(
        template,
        short_name="ABCD",
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    short_result = next(r for r in results if r.field == "short_name")
    assert short_result.status == WriteStatus.CONFIRMED
    assert "truncated" in short_result.message


def test_verify_plan_empty_name_readback_is_unconfirmed_not_truncated(make_live) -> None:
    """An empty read-back is not truncation -- it's an unavailable NodeDB read.

    getMyUser() (the source of both short_name/long_name) can legitimately
    return None right after a reboot, before the NodeDB entry repopulates --
    the same condition _verify_key_material already treats as unavailable
    for the sibling getPublicKey() read. Before this guard,
    "".startswith("") was trivially satisfied and this was misreported
    CONFIRMED, silently persisting a blank name over a good one. See
    Round 35's plan-apply review.
    """
    template = _template()
    live = make_live(template, short_name="OLD1", security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="MT00",
    )
    plan = build_plan(inputs)
    assert plan.name_change.short_changed
    live_after = make_live(
        template,
        short_name="",
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    short_result = next(r for r in results if r.field == "short_name")
    assert short_result.status == WriteStatus.UNCONFIRMED
    assert "truncated" not in short_result.message


def test_verify_plan_key_confirmed_needs_both_agree(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=kp.public_b64)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.CONFIRMED


def test_verify_plan_key_rejects_noncanonically_encoded_nodedb_key(make_live) -> None:
    """Reject a non-canonically-encoded NodeDB key rather than confirm it.

    A NodeDB public key that decodes to the right bytes via non-canonical
    base64 (stray padding bits) must not be silently confirmed -- it should
    go through the same strict decode (:func:`crypto.keys.decode_key`) used
    everywhere else key material is decoded, not a hand-rolled, more lenient
    ``base64.b64decode``.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    canonical = base64.b64encode(kp.public).decode("ascii")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    noncanonical = next(
        candidate
        for c in alphabet
        if (candidate := canonical[:-2] + c + canonical[-1]) != canonical
        and base64.b64decode(candidate, validate=True) == kp.public
    )

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=noncanonical)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.UNCONFIRMED
    # The NodeDB value never became comparable at all -- distinct from a
    # decoded-but-differs mismatch, whose `actual` is a key fingerprint.
    assert key_result.actual is not None
    assert "did not decode" in key_result.actual
    assert "non-canonical base64 encoding" in key_result.actual


def test_verify_plan_key_mismatch_unconfirmed_with_fingerprints(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()
    other_kp = generate_keypair()

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=other_kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=other_kp.public_b64)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.UNCONFIRMED
    assert key_result.expected is not None and key_result.expected.startswith("sha256:")
    assert key_result.actual is not None and key_result.actual.startswith("sha256:")


def test_verify_plan_key_none_device_public_key_confirmed_with_note(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(keypair=kp),
    )
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=None)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.CONFIRMED
    assert "NodeDB cross-check unavailable" in key_result.message


def test_verify_plan_adopt_device_key_confirmed_when_still_present(
    make_live, keypair_factory
) -> None:
    kp = keypair_factory()
    other_kp = keypair_factory()
    plan = adopt_device_key_plan(make_live, kp, other_kp)

    live_after = make_live(_template(), security=make_security(keypair=kp))
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=kp.public_b64)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.CONFIRMED


def test_verify_plan_adopt_device_key_unconfirmed_when_key_reverts_across_reboot(
    make_live, keypair_factory
) -> None:
    """Regression test for firmware issue #7449.

    The adopted key must be re-verified after this run's writes, not
    assumed to still be present. An earlier section's write in the same
    plan can trigger a reboot that silently reverts a key that was never
    even written this run.
    """
    kp = keypair_factory()
    other_kp = keypair_factory()
    reverted_kp = keypair_factory()
    plan = adopt_device_key_plan(make_live, kp, other_kp)

    # Simulates the device's key reverting across a reboot triggered by some
    # other section write earlier in the same plan -- kp was on the device
    # when detected, but is no longer there by the time this run verifies.
    live_after = make_live(_template(), security=make_security(keypair=reverted_kp))
    results = verify_plan(plan, live_after, keypair=kp, device_public_key=reverted_kp.public_b64)
    key_result = next(r for r in results if r.field == "public_key")
    assert key_result.status == WriteStatus.UNCONFIRMED


def test_verify_plan_admin_keys_compared_sorted(make_live, make_admin_key) -> None:
    admin1 = make_admin_key("ADMIN1")
    template = _template().model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1,),
    )
    plan = build_plan(inputs)

    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(admin_keys=(admin1.public,)),
    )
    results = verify_plan(plan, live_after, keypair=None)
    admin_result = next(r for r in results if r.field == "admin_key")
    assert admin_result.status == WriteStatus.CONFIRMED


def test_verify_plan_admin_keys_mismatch_is_unconfirmed(make_live, make_admin_key) -> None:
    """The admin-key write-verify mismatch branch, never exercised by any existing test.

    Every other admin-key verify test (including the CONFIRMED case just
    above) reports the device holding exactly the desired keys -- this is
    a security-relevant write-verify check, so its failure path deserves
    direct coverage, not just the happy path.
    """
    admin1 = make_admin_key("ADMIN1")
    template = _template().model_copy(update={"admin_nodes": ("ADMIN1",)})
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin1,),
    )
    plan = build_plan(inputs)

    # The device's post-write admin_key list is empty, not the desired ADMIN1 key.
    live_after = make_live(
        template,
        short_name=plan.name_change.desired_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)
    admin_result = next(r for r in results if r.field == "admin_key")
    assert admin_result.status == WriteStatus.UNCONFIRMED
    assert admin_result.expected is not None and admin_result.expected.startswith("sha256:")
    assert admin_result.actual == "<none>"
