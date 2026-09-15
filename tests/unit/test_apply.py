"""Tests for meshprovision.provisioning.apply (no real device)."""

from __future__ import annotations

import base64
import dataclasses

import pytest
from meshtastic.protobuf import localonly_pb2

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.crypto.keys import KeyPair, encode_key, generate_keypair
from meshprovision.db.keys import KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.errors import (
    AtomicWriteError,
    ConnectionBackendError,
    ConnectionFailedError,
    EnumMappingError,
    ExitCode,
    PlanConflictError,
    ProvisioningError,
    UnsupportedTransportError,
    WriteVerificationError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import apply as apply_module
from meshprovision.provisioning import detect
from meshprovision.provisioning.apply import (
    DEFAULT_SETTLE_SECONDS,
    ApplyOutcome,
    InPlaceSession,
    ReconnectingSession,
    WriteResult,
    WriteStatus,
    apply_field,
    apply_plan,
    generate_ble_pin,
    persist_result,
    verify_plan,
    write_section,
)
from meshprovision.provisioning.plan import (
    ChangePlan,
    FieldChange,
    PlanInputs,
    SectionChange,
    build_plan,
)
from meshprovision.provisioning.plan_admin_keys import KeyPlan
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# generate_ble_pin.
# ---------------------------------------------------------------------------


def test_generate_ble_pin_with_injected_rng() -> None:
    pin = generate_ble_pin(rng=lambda _bound: 0)
    assert pin == "000000"
    assert len(pin) == 6
    assert pin.isdigit()


def test_generate_ble_pin_real_calls_are_six_digits() -> None:
    for _ in range(200):
        pin = generate_ble_pin()
        assert len(pin) == 6
        assert pin.isdigit()


# ---------------------------------------------------------------------------
# apply_field.
# ---------------------------------------------------------------------------


def _local_config() -> localonly_pb2.LocalConfig:
    return localonly_pb2.LocalConfig()


def test_apply_field_enum_by_name() -> None:
    msg = _local_config().device
    apply_field(msg, "role", "ROUTER")
    assert msg.role == 2


def test_apply_field_unknown_enum_name_raises() -> None:
    msg = _local_config().device
    with pytest.raises(EnumMappingError) as exc_info:
        apply_field(msg, "role", "NOT_A_ROLE")
    assert exc_info.value.known


def test_apply_field_numeric_string_into_int_field() -> None:
    msg = _local_config().lora
    apply_field(msg, "hop_limit", "5")
    assert msg.hop_limit == 5


def test_apply_field_bad_numeric_string_raises() -> None:
    msg = _local_config().lora
    with pytest.raises(PlanConflictError):
        apply_field(msg, "hop_limit", "not-a-number")


def test_apply_field_out_of_range_int_raises_plan_conflict_not_value_error() -> None:
    """Protobuf's own range check raises a bare ValueError -- must be converted.

    node_info_broadcast_secs is one of several config.template.py fields
    declared with only a lower bound (``ge=0``), so an operator typo with
    an extra digit reaches this call unvalidated by pydantic.
    """
    msg = _local_config().device
    with pytest.raises(PlanConflictError) as exc_info:
        apply_field(msg, "node_info_broadcast_secs", 99999999999)
    assert "node_info_broadcast_secs" in str(exc_info.value)


def test_apply_field_bool_int_float_str_bytes() -> None:
    msg = _local_config().lora
    apply_field(msg, "tx_enabled", False)
    assert msg.tx_enabled is False
    apply_field(msg, "hop_limit", 4)
    assert msg.hop_limit == 4
    apply_field(msg, "frequency_offset", 1.5)
    assert msg.frequency_offset == pytest.approx(1.5)

    security_msg = _local_config().security
    apply_field(security_msg, "public_key", bytes(range(32)))
    assert bytes(security_msg.public_key) == bytes(range(32))


def test_apply_field_unknown_field_raises() -> None:
    msg = _local_config().device
    with pytest.raises(PlanConflictError):
        apply_field(msg, "not_a_real_field", "x")


def test_apply_field_unsupported_type_raises() -> None:
    msg = _local_config().device
    with pytest.raises(PlanConflictError):
        apply_field(msg, "role", object())


def test_write_result_as_error_carries_the_redacted_fields_through() -> None:
    """`WriteResult.as_error()` -- `__all__`-exported public API, unused internally.

    `cli/provision.py` reimplements similar rendering inline for its own
    CLI-specific message formatting, but this convenience method for
    library consumers wanting a proper typed exception from a
    `WriteResult` had zero test coverage.
    """
    result = WriteResult(
        "security",
        WriteStatus.UNCONFIRMED,
        "admin key set mismatch: expected 1, got 0",
        field="admin_key",
        expected="sha256:aaaa",
        actual="<none>",
    )

    error = result.as_error()

    assert isinstance(error, WriteVerificationError)
    assert error.section == "security"
    assert error.field == "admin_key"
    assert error.expected == "sha256:aaaa"
    assert error.actual == "<none>"
    assert "admin key set mismatch" in str(error)


def test_write_section_unknown_section_raises() -> None:
    iface = _FakeIfaceForApply()
    change = SectionChange(section="not_a_real_section", kind=detect.SectionKind.CONFIG, changes=())
    with pytest.raises(PlanConflictError):
        write_section(iface, change)  # type: ignore[arg-type]


def test_write_section_regenerate_without_a_keypair_raises() -> None:
    """`write_section`'s own regenerate+keypair=None guard, called directly.

    `apply_plan` never triggers this in practice -- it always resolves a
    keypair before calling write_section when key_plan.regenerate is set
    -- but write_section is `__all__`-exported and this internal
    consistency check has its own error message/type worth pinning down
    directly, the same way the unknown-section guard just above is.
    """
    iface = _FakeIfaceForApply()
    change = SectionChange(section="security", kind=detect.SectionKind.CONFIG, changes=())
    key_plan = KeyPlan(regenerate=True)

    with pytest.raises(PlanConflictError, match="fresh keypair"):
        write_section(iface, change, key_plan=key_plan, keypair=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A minimal fake interface for write/verify tests.
# ---------------------------------------------------------------------------


class _FakeLocalNode:
    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface
        self.localConfig = localonly_pb2.LocalConfig()
        self.moduleConfig = localonly_pb2.LocalModuleConfig()
        self.written_sections: list[str] = []

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        self.written_sections.append(section)

    def setOwner(  # noqa: N802 -- real MeshInterface method name
        self,
        long_name: str | None = None,
        short_name: str | None = None,
        **_kw: object,
    ) -> None:
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name


class _FakeIfaceForApply:
    def __init__(self) -> None:
        from types import SimpleNamespace

        self.myInfo = SimpleNamespace(my_node_num=0xDEADBE01)
        self.metadata = SimpleNamespace(hw_model="RAK4631", firmware_version="2.7.11")
        self.user: dict[str, str] = {"shortName": "MT00", "longName": "Meshtastic MT00"}
        self.localNode = _FakeLocalNode(self)

    def getMyUser(self) -> dict[str, str]:  # noqa: N802 -- real MeshInterface method name
        return dict(self.user)

    def getPublicKey(self) -> str | None:  # noqa: N802 -- real MeshInterface method name
        raw = bytes(self.localNode.localConfig.security.public_key)
        return base64.b64encode(raw).decode("ascii") if raw else None


# ---------------------------------------------------------------------------
# verify_plan.
# ---------------------------------------------------------------------------


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


def test_apply_reuses_plan_values_equal() -> None:
    from meshprovision.provisioning import apply as apply_mod
    from meshprovision.provisioning import plan as plan_mod

    assert apply_mod.values_equal is plan_mod.values_equal


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
    result = apply_module._verify_key_material(
        plan, live_after, keypair=kp, device_public_key=encode_key(wrong_kp.public)
    )

    assert result is not None
    assert result.status == WriteStatus.UNCONFIRMED


def test_confirmed_name_ignores_a_different_fields_actual_value() -> None:
    """_confirmed_name must not return a truncated OTHER field's actual value.

    Both the section and field checks are load-bearing: an owner-section
    result for the field NOT being asked about must never be mistaken
    for the one that is, even when that other field's write was itself
    truncated (actual is not None).
    """
    results = (
        WriteResult(
            "owner",
            WriteStatus.CONFIRMED,
            "long_name truncated on write",
            field="long_name",
            actual="Meshtastic ABCDEFGHIJ",
        ),
        WriteResult("owner", WriteStatus.CONFIRMED, "short_name confirmed", field="short_name"),
    )

    assert apply_module._confirmed_name(results, "short_name") is None


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


def test_verify_plan_only_long_name_changed_does_not_affect_short_name_result(
    make_live,
) -> None:
    """Verifying two independent name fields when only one of them actually changed.

    Every existing name-verify test changes both short_name and long_name
    (a fresh FACTORY device) or neither -- forced here via
    dataclasses.replace to pin desired_short_name back to its own current
    value, simulating a device whose short_name already fit the pattern
    while long_name still needed rewriting. Confirms short_name's
    trivially-already-correct result doesn't interfere with or get
    conflated with long_name's own, separately-computed result.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    plan = dataclasses.replace(
        plan,
        name_change=dataclasses.replace(
            plan.name_change, desired_short_name=plan.name_change.current_short_name
        ),
    )

    live_after = make_live(
        template,
        short_name=plan.name_change.current_short_name,
        long_name=plan.name_change.desired_long_name,
        security=make_security(empty=True),
    )
    results = verify_plan(plan, live_after, keypair=None)

    short_result = next(r for r in results if r.field == "short_name")
    long_result = next(r for r in results if r.field == "long_name")
    assert short_result.status == WriteStatus.CONFIRMED
    assert long_result.status == WriteStatus.CONFIRMED


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


def _adopt_device_key_plan(make_live, kp: KeyPair, other_kp: KeyPair) -> ChangePlan:
    """Build a plan whose key_plan.adopt_device_key is True (db key differs from live)."""
    template = _template()
    live = make_live(template, security=make_security(keypair=kp))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        db_public_key=other_kp.public,
    )
    plan = build_plan(inputs)
    assert plan.key_plan.adopt_device_key is True
    assert plan.key_plan.regenerate is False
    return plan


def test_verify_plan_adopt_device_key_confirmed_when_still_present(
    make_live, keypair_factory
) -> None:
    kp = keypair_factory()
    other_kp = keypair_factory()
    plan = _adopt_device_key_plan(make_live, kp, other_kp)

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
    plan = _adopt_device_key_plan(make_live, kp, other_kp)

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


# ---------------------------------------------------------------------------
# ApplyOutcome.
# ---------------------------------------------------------------------------


def test_apply_outcome_properties() -> None:
    ok_result = WriteResult("device", WriteStatus.CONFIRMED, "confirmed")
    outcome = ApplyOutcome(node_id=_node_id(), results=(ok_result,), dry_run=False)
    assert outcome.ok is True
    assert outcome.uncertain is False
    assert outcome.may_update_database is True
    assert outcome.exit_code == 0
    assert outcome.failures() == ()
    assert outcome.describe() == ("device: confirmed -- confirmed",)


def test_apply_outcome_uncertain_and_failures() -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(node_id=_node_id(), results=(bad_result,), dry_run=False)
    assert outcome.uncertain is True
    assert outcome.ok is False
    assert outcome.may_update_database is False
    assert outcome.exit_code != 0
    assert outcome.failures() == (bad_result,)


def test_apply_outcome_dry_run_never_updates_database_even_if_ok() -> None:
    ok_result = WriteResult("device", WriteStatus.SKIPPED, "dry run")
    outcome = ApplyOutcome(node_id=_node_id(), results=(ok_result,), dry_run=True)
    assert outcome.ok is True
    assert outcome.may_update_database is False


def _node_id() -> NodeId:
    return NodeId.from_hex("deadbe01")


# ---------------------------------------------------------------------------
# apply_plan / persist_result, over InPlaceSession + fake interface.
# ---------------------------------------------------------------------------


def test_apply_plan_regenerate_without_keypair_raises_before_write(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.key_plan.regenerate is True

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    with pytest.raises(PlanConflictError):
        apply_plan(plan, session, keypair=None)
    assert iface.localNode.written_sections == []


def test_apply_plan_dry_run_never_writes(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp, dry_run=True)
    assert outcome.dry_run is True
    assert iface.localNode.written_sections == []
    assert all(r.status == WriteStatus.SKIPPED for r in outcome.results)


def test_apply_plan_success_confirmed_and_persist_result(tmp_path, make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    # An in-place session re-reads from the SAME iface, so the write must be
    # reflected there for verification to succeed -- write_section() does
    # this by mutating iface.localNode.localConfig directly.
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.dry_run is False
    assert outcome.verified is True
    assert outcome.ok is True, outcome.describe()
    assert outcome.record is not None

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)
    persisted = persist_result(outcome, nodes=nodes, keys=keys, keypair=kp)
    assert persisted is True
    assert nodes.exists("deadbe01")
    assert keys.find("deadbe01_pub") is not None
    assert keys.find("deadbe01_priv") is not None


def test_apply_plan_sleeps_only_once_for_a_reboot_on_the_last_section(make_live) -> None:
    """A reboot on the last section (typically "security") must settle once, not twice.

    The loop's own settle sleep is only needed ahead of a mid-loop
    refresh; the last section's reboot is already covered by the
    unconditional sleep right before the final verify reconnect.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert [s.section for s in plan.sections] == ["security"]
    assert plan.sections[0].reboots_device is True
    kp = generate_keypair()

    sleep_calls: list[float] = []
    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp, sleep=sleep_calls.append)

    assert outcome.ok is True, outcome.describe()
    assert sleep_calls == [DEFAULT_SETTLE_SECONDS]


def test_apply_plan_persists_the_truncated_name_not_the_desired_one(tmp_path, make_live) -> None:
    """A truncated-but-CONFIRMED name write must persist what's really on the device.

    Persisting the longer desired value instead would make the next run
    re-diff against a name the device doesn't have, re-plan the same
    rewrite, get truncated again, and never converge.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_long_name="Meshtastic ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    )
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceTruncatesLongName()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is True, outcome.describe()
    long_result = next(r for r in outcome.results if r.field == "long_name")
    assert long_result.status == WriteStatus.CONFIRMED
    assert "truncated" in long_result.message

    assert outcome.record is not None
    assert outcome.record.long_name == plan.name_change.desired_long_name[:20]
    assert outcome.record.long_name != plan.name_change.desired_long_name


def test_apply_plan_an_unmappable_enum_value_fails_its_section_not_the_whole_run(
    tmp_path, make_live
) -> None:
    """Cover apply_plan's per-section enum-mapping failure handling.

    A bad enum value (e.g. a typo'd, unvalidated ``rebroadcast_mode``/
    ``modem_preset`` in the template) must degrade to a FAILED WriteResult
    for its own section, not crash apply_plan and abandon sections already
    written to the device with no verify/persist pass at all.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    good_device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    bad_lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(
            FieldChange(
                section="lora", field="modem_preset", current="LONG_FAST", desired="NOT_A_PRESET"
            ),
        ),
    )
    plan = dataclasses.replace(plan, sections=(good_device_change, bad_lora_change))

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is False
    lora_result = next(r for r in outcome.results if r.section == "lora")
    assert lora_result.status == WriteStatus.FAILED
    assert "modem_preset" in lora_result.message or "NOT_A_PRESET" in lora_result.message

    # The device section, processed before the lora failure, was genuinely
    # written and still reaches the verify pass.
    assert "device" in iface.localNode.written_sections
    role_result = next(r for r in outcome.results if r.field == "role")
    assert role_result.status == WriteStatus.CONFIRMED


def test_apply_plan_owner_write_failure_reports_failed_not_a_crash(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="MT01",
        desired_long_name="Meshtastic MT01",
    )
    plan = build_plan(inputs)
    assert not plan.name_change.is_empty
    kp = generate_keypair()

    iface = _FakeIfaceRaisesOnSetOwner()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is False
    owner_result = next(r for r in outcome.results if r.section == "owner")
    assert owner_result.status == WriteStatus.FAILED
    assert "Failed to set owner" in owner_result.message


class _FakeSessionTracksRefresh:
    """A session whose refresh() swaps in a second, distinct fake interface.

    Lets a test tell apart "wrote to the pre-reboot interface" from "wrote
    to the post-reboot, refreshed interface".
    """

    def __init__(self, first: _FakeIfaceForApply, refreshed: _FakeIfaceForApply) -> None:
        self._iface: _FakeIfaceForApply = first
        self._refreshed = refreshed
        self.refresh_calls = 0

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    def describe(self) -> str:
        return "fake (tracks refresh calls)"

    def refresh(self) -> _FakeIfaceForApply:
        self.refresh_calls += 1
        self._iface = self._refreshed
        return self._iface


class _FakeSessionRefreshFailsAfterFirstCall:
    """A session whose refresh() raises on its first call -- the mid-loop reboot case."""

    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    def describe(self) -> str:
        return "fake (refresh fails)"

    def refresh(self) -> _FakeIfaceForApply:
        raise ConnectionBackendError("link dropped after reboot", transport="serial")


def test_apply_plan_reconnects_mid_loop_after_a_reboot_before_writing_later_sections(
    make_live,
) -> None:
    """A reboot-triggering section that isn't last must not leave later writes stale.

    lora.region/modem_preset changes reboot the device; if a later section
    (e.g. device) is written against the same never-refreshed interface,
    it's written into (or later read back from) a stale, possibly-dead
    handle instead of a genuinely fresh connection.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    rebooting_lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="hop_limit", current=3, desired=5),),
        reboots_device=True,
    )
    later_device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    plan = dataclasses.replace(plan, sections=(rebooting_lora_change, later_device_change))

    first_iface = _FakeIfaceForApply()
    refreshed_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, refreshed_iface)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    # One mid-loop refresh (after "lora" reboots, before "device"), plus the
    # unconditional final-verify refresh at the end of apply_plan.
    assert session.refresh_calls == 2
    assert "lora" in first_iface.localNode.written_sections
    assert "device" not in first_iface.localNode.written_sections
    assert "device" in refreshed_iface.localNode.written_sections
    role_result = next(r for r in outcome.results if r.field == "role")
    assert role_result.status == WriteStatus.CONFIRMED


def test_apply_plan_reports_uncertain_when_mid_loop_reconnect_fails(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    rebooting_lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="hop_limit", current=3, desired=5),),
        reboots_device=True,
    )
    later_device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    plan = dataclasses.replace(plan, sections=(rebooting_lora_change, later_device_change))

    iface = _FakeIfaceForApply()
    session = _FakeSessionRefreshFailsAfterFirstCall(iface)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert outcome.verified is True
    assert outcome.ok is False
    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "reconnect" in verify_result.message
    # The device section must never be attempted once the mid-loop
    # reconnect is known to have failed -- the connection is dead.
    assert "device" not in iface.localNode.written_sections


# ---------------------------------------------------------------------------
# ReconnectingSession.refresh() -- the real retry-with-backoff logic, not a
# hand-rolled fake session double.
# ---------------------------------------------------------------------------


class _FakeReconnectBackend:
    """A ConnectionBackend double: connect() replays a scripted outcome sequence."""

    def __init__(self, outcomes: list[object]) -> None:
        self._outcomes = list(outcomes)
        self.connect_calls = 0

    @property
    def transport(self) -> str:
        return "serial"

    @property
    def target(self) -> str:
        return "/dev/ttyFAKE"

    def describe(self) -> str:
        return "fake"

    def connect(self) -> object:
        outcome = self._outcomes[self.connect_calls]
        self.connect_calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _FakeIfaceForReconnect:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_reconnecting_session_interface_raises_before_open() -> None:
    """Reading `.interface` before `open()`/`refresh()` must raise, not return None-ish garbage.

    Untested caller-error guard: every existing test always calls
    `open()` or `refresh()` first, so this branch had zero coverage.
    """
    backend = _FakeReconnectBackend([_FakeIfaceForReconnect()])
    session = ReconnectingSession(backend=backend, sleep=lambda _: None)  # type: ignore[arg-type]

    with pytest.raises(ProvisioningError):
        _ = session.interface


def test_reconnecting_session_refresh_succeeds_on_first_attempt() -> None:
    iface = _FakeIfaceForReconnect()
    backend = _FakeReconnectBackend([iface])
    sleeps: list[float] = []
    session = ReconnectingSession(backend=backend, sleep=sleeps.append)  # type: ignore[arg-type]

    result = session.refresh()

    assert result is iface
    assert backend.connect_calls == 1
    assert sleeps == [DEFAULT_SETTLE_SECONDS]


def test_reconnecting_session_refresh_retries_then_succeeds() -> None:
    iface = _FakeIfaceForReconnect()
    fail1 = ConnectionFailedError("nope", transport="serial", target="/dev/ttyFAKE")
    fail2 = ConnectionFailedError("still nope", transport="serial", target="/dev/ttyFAKE")
    backend = _FakeReconnectBackend([fail1, fail2, iface])
    sleeps: list[float] = []
    session = ReconnectingSession(
        backend=backend,  # type: ignore[arg-type]
        attempts=3,
        sleep=sleeps.append,
    )

    result = session.refresh()

    assert result is iface
    assert backend.connect_calls == 3
    assert sleeps == [
        DEFAULT_SETTLE_SECONDS,
        apply_module._RECONNECT_BACKOFF * 1,
        apply_module._RECONNECT_BACKOFF * 2,
    ]


def test_reconnecting_session_refresh_exhausts_all_attempts_and_raises() -> None:
    fail = ConnectionFailedError("nope", transport="serial", target="/dev/ttyFAKE")
    backend = _FakeReconnectBackend([fail, fail, fail])
    sleeps: list[float] = []
    session = ReconnectingSession(
        backend=backend,  # type: ignore[arg-type]
        attempts=3,
        sleep=sleeps.append,
    )

    with pytest.raises(ConnectionFailedError):
        session.refresh()

    assert backend.connect_calls == 3
    # No backoff sleep after the last (3rd) attempt -- only 2 retries follow attempts 1-2.
    assert sleeps == [
        DEFAULT_SETTLE_SECONDS,
        apply_module._RECONNECT_BACKOFF * 1,
        apply_module._RECONNECT_BACKOFF * 2,
    ]


def test_reconnecting_session_refresh_wraps_non_connectionfailed_backend_error() -> None:
    backend = _FakeReconnectBackend([UnsupportedTransportError("no ble", transport="ble")])
    session = ReconnectingSession(
        backend=backend,  # type: ignore[arg-type]
        attempts=1,
        sleep=lambda _: None,
    )

    with pytest.raises(ConnectionFailedError) as exc_info:
        session.refresh()

    assert exc_info.value.transport == "serial"
    assert "no ble" in str(exc_info.value)


def test_reconnecting_session_refresh_closes_the_existing_interface_first() -> None:
    old_iface = _FakeIfaceForReconnect()
    new_iface = _FakeIfaceForReconnect()
    backend = _FakeReconnectBackend([new_iface])
    session = ReconnectingSession(backend=backend, sleep=lambda _: None)  # type: ignore[arg-type]
    session._iface = old_iface  # type: ignore[assignment]

    result = session.refresh()

    assert old_iface.closed is True
    assert result is new_iface


class _RefreshFailsSession:
    """A session whose reconnect never succeeds -- pins the lost-reconnect path."""

    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    def describe(self) -> str:
        return "fake (refresh always fails)"

    def refresh(self) -> _FakeIfaceForApply:
        raise ConnectionBackendError("link dropped", transport="serial")


def test_apply_plan_reports_uncertain_when_the_reconnect_fails(tmp_path, make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = _RefreshFailsSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.dry_run is False
    assert outcome.verified is True
    assert outcome.uncertain is True
    assert outcome.may_update_database is False

    verify_results = [r for r in outcome.results if r.section == "<verify>"]
    assert len(verify_results) == 1
    assert verify_results[0].status == WriteStatus.FAILED
    assert verify_results[0].message == "Could not reconnect to verify the writes"


def test_apply_plan_keeps_an_earlier_section_failure_when_the_final_reconnect_also_fails(
    make_live,
) -> None:
    """A pre-verify section failure must not be lost when the final reconnect also fails.

    Both early-return branches append to the same accumulating `results`
    list rather than replacing it, but that's exactly the kind of thing a
    regression could silently break.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    bad_lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(
            FieldChange(
                section="lora", field="modem_preset", current="LONG_FAST", desired="NOT_A_PRESET"
            ),
        ),
    )
    plan = dataclasses.replace(plan, sections=(bad_lora_change,))

    iface = _FakeIfaceForApply()
    session = _RefreshFailsSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is False
    lora_result = next(r for r in outcome.results if r.section == "lora")
    assert lora_result.status == WriteStatus.FAILED
    verify_results = [r for r in outcome.results if r.section == "<verify>"]
    assert len(verify_results) == 1
    assert verify_results[0].status == WriteStatus.FAILED


class _FakeIfaceRaisesOnUser(_FakeIfaceForApply):
    """A fresh interface whose reconnect succeeded but whose user read fails.

    ``getMyUser`` is the read ``detect.read_live_config`` actually calls
    unconditionally -- ``getMyNodeInfo`` is only consulted when ``myInfo``
    is ``None``, which it never is on this fake -- so this is the read
    that must fail to reach the ``DetectionError`` branch under test.
    """

    def getMyUser(self) -> dict[str, str]:  # noqa: N802 -- real MeshInterface method name
        raise ValueError("serial read timed out")


class _FakeIfaceRaisesOnPublicKey(_FakeIfaceForApply):
    """A fresh interface whose reconnect succeeded but whose key read fails."""

    def getPublicKey(self) -> str | None:  # noqa: N802 -- real MeshInterface method name
        raise RuntimeError("serial read timed out")


class _FakeLocalNodeTruncatesLongName(_FakeLocalNode):
    """Simulates firmware silently truncating an over-length long_name on write."""

    def setOwner(  # noqa: N802 -- real MeshInterface method name
        self,
        long_name: str | None = None,
        short_name: str | None = None,
        **_kw: object,
    ) -> None:
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name[:20]


class _FakeIfaceTruncatesLongName(_FakeIfaceForApply):
    """An interface whose firmware truncates every long_name write to 20 bytes."""

    def __init__(self) -> None:
        super().__init__()
        self.localNode = _FakeLocalNodeTruncatesLongName(self)


class _FakeLocalNodeRaisesOnSetOwner(_FakeLocalNode):
    """Simulates a device/communication failure during the owner (name) write."""

    def setOwner(self, **_kw: object) -> None:  # noqa: N802 -- real MeshInterface method name
        raise OSError("serial write timed out")


class _FakeIfaceRaisesOnSetOwner(_FakeIfaceForApply):
    """An interface whose owner (name) write always raises."""

    def __init__(self) -> None:
        super().__init__()
        self.localNode = _FakeLocalNodeRaisesOnSetOwner(self)


class _ReadFailsAfterReconnectSession:
    """A session whose reconnect succeeds but returns a fresh, failing interface."""

    def __init__(self, write_iface: _FakeIfaceForApply, fresh_iface: _FakeIfaceForApply) -> None:
        self._write_iface = write_iface
        self._fresh_iface = fresh_iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._write_iface

    def describe(self) -> str:
        return "fake (reconnect succeeds, post-reconnect read fails)"

    def refresh(self) -> _FakeIfaceForApply:
        return self._fresh_iface


def test_verify_reports_uncertain_when_the_post_reconnect_read_fails(tmp_path, make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    write_iface = _FakeIfaceForApply()
    fresh_iface = _FakeIfaceRaisesOnUser()
    session = _ReadFailsAfterReconnectSession(write_iface, fresh_iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert outcome.dry_run is False
    assert outcome.verified is True
    assert outcome.uncertain is True
    assert outcome.may_update_database is False

    verify_results = [r for r in outcome.results if r.section == "<verify>"]
    assert len(verify_results) == 1
    assert verify_results[0].status == WriteStatus.FAILED
    assert verify_results[0].message != "Could not reconnect to verify the writes"
    assert "could not read back the device state to verify" in verify_results[0].message


def test_verify_reports_uncertain_when_get_public_key_raises(tmp_path, make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    write_iface = _FakeIfaceForApply()
    fresh_iface = _FakeIfaceRaisesOnPublicKey()
    session = _ReadFailsAfterReconnectSession(write_iface, fresh_iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert outcome.dry_run is False
    assert outcome.verified is True
    assert outcome.uncertain is True
    assert outcome.may_update_database is False

    verify_results = [r for r in outcome.results if r.section == "<verify>"]
    assert len(verify_results) == 1
    assert verify_results[0].status == WriteStatus.FAILED
    assert verify_results[0].message != "Could not reconnect to verify the writes"
    assert "could not read back the device state to verify" in verify_results[0].message

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)
    mtime_before = db_path.stat().st_mtime_ns
    persisted = persist_result(outcome, nodes=nodes, keys=keys, keypair=kp)
    assert persisted is False
    assert db_path.stat().st_mtime_ns == mtime_before
    assert nodes.exists("deadbe01") is False


def test_persist_result_refuses_on_uncertain_outcome(tmp_path) -> None:
    bad_result = WriteResult("security", WriteStatus.UNCONFIRMED, "mismatch", field="public_key")
    outcome = ApplyOutcome(node_id=_node_id(), results=(bad_result,), dry_run=False, record=None)

    db_path = tmp_path / "db.ods"
    db = OdsDatabase.create(db_path)
    nodes = NodeRepository(db)
    keys = KeyRepository(db)

    mtime_before = db_path.stat().st_mtime_ns
    persisted = persist_result(outcome, nodes=nodes, keys=keys)
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

    persisted = persist_result(outcome, nodes=nodes, keys=keys)
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
        persist_result(outcome, nodes=nodes, keys=keys, keypair=kp)

    assert "written and verified on the device" in excinfo.value.message
    assert "could not be saved" in excinfo.value.message
    assert "disagree" in excinfo.value.message
    assert "disk went away" in excinfo.value.message
    assert "deadbe01" in excinfo.value.message
    assert excinfo.value.__cause__ is not None
    assert excinfo.value.exit_code == ExitCode.DB
    assert "--force-regenerate-key" in excinfo.value.user_message
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
        persist_result(outcome, nodes=nodes, keys=keys, keypair=kp)

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
        persist_result(outcome, nodes=nodes, keys=keys, keypair=None)

    assert "--force-regenerate-key" not in excinfo.value.user_message
    assert "re-run `mesh provision`" in excinfo.value.user_message
    assert "--enroll" in excinfo.value.user_message
