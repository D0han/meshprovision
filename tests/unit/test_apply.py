"""Tests for meshprovision.provisioning.apply (no real device)."""

from __future__ import annotations

import base64
import dataclasses
import errno
import logging
from collections.abc import Callable
from typing import Final, Self

import pytest
from meshtastic.protobuf import channel_pb2, localonly_pb2

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.crypto import redact
from meshprovision.crypto.keys import generate_keypair
from meshprovision.db.keys import KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyOrigin
from meshprovision.errors import (
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
from meshprovision.provisioning import apply_session as apply_session_module
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
    write_default_channel,
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
from tests.conftest import real_write_config_or_exit
from tests.unit.conftest import adopt_device_key_plan, make_security

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

    node_info_broadcast_secs is one of several config/template_sections.py fields
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
# write_default_channel.
# ---------------------------------------------------------------------------


def test_write_default_channel_applies_fields_and_calls_write_channel() -> None:
    iface = _FakeIfaceForApply()
    change = SectionChange(
        section="default_channel",
        kind=detect.SectionKind.CHANNEL,
        changes=(
            FieldChange(
                section="default_channel", field="position_precision", current=0, desired=12
            ),
            FieldChange(section="default_channel", field="is_muted", current=False, desired=True),
        ),
    )

    write_default_channel(iface, change)  # type: ignore[arg-type]

    channel = iface.localNode.channels[0]
    assert channel.settings.module_settings.position_precision == 12
    assert channel.settings.module_settings.is_muted is True
    assert iface.localNode.written_sections == ["default_channel"]


def test_write_default_channel_no_primary_channel_raises() -> None:
    iface = _FakeIfaceForApply()
    iface.localNode.channels = []
    change = SectionChange(
        section="default_channel",
        kind=detect.SectionKind.CHANNEL,
        changes=(
            FieldChange(
                section="default_channel", field="position_precision", current=0, desired=12
            ),
        ),
    )

    with pytest.raises(PlanConflictError, match="not available") as exc_info:
        write_default_channel(iface, change)  # type: ignore[arg-type]

    assert exc_info.value.field == "default_channel"
    assert iface.localNode.written_sections == []


def test_write_default_channel_disabled_primary_channel_raises_before_any_write() -> None:
    """A DISABLED channel 0 is refused pre-I/O and left exactly as it was.

    ``writeChannel(0)`` sends the whole channel, so writing a disabled
    one (the library's placeholder role) would overwrite the device's
    primary channel with a near-empty one.
    """
    iface = _FakeIfaceForApply()
    iface.localNode.channels[0].role = channel_pb2.Channel.Role.DISABLED
    pre_call = channel_pb2.Channel()
    pre_call.CopyFrom(iface.localNode.channels[0])
    change = SectionChange(
        section="default_channel",
        kind=detect.SectionKind.CHANNEL,
        changes=(
            FieldChange(
                section="default_channel", field="position_precision", current=0, desired=12
            ),
        ),
    )

    with pytest.raises(PlanConflictError, match="disabled") as exc_info:
        write_default_channel(iface, change)  # type: ignore[arg-type]

    assert exc_info.value.field == "default_channel"
    assert iface.localNode.channels[0] == pre_call
    assert iface.localNode.written_sections == []


def test_write_default_channel_refuses_exactly_what_detect_reads_as_absent() -> None:
    """The write path and detect agree on which channel 0 has no settings to write.

    Round 39 E39-2: detect read a DISABLED channel 0 as ``{}`` while the
    write path only refused a missing one -- so the plan kept proposing
    a write that clobbered the channel and never verified.
    """
    change = SectionChange(section="default_channel", kind=detect.SectionKind.CHANNEL, changes=())
    seen: dict[str, tuple[bool, bool]] = {}
    for role in (None, *channel_pb2.Channel.Role.values()):
        iface = _FakeIfaceForApply()
        if role is None:
            iface.localNode.channels = []
        else:
            iface.localNode.channels[0].role = role  # type: ignore[assignment]
        reads_absent = detect.read_live_config(iface).default_channel == {}  # type: ignore[arg-type]
        try:
            write_default_channel(iface, change)  # type: ignore[arg-type]
        except PlanConflictError:
            refused = True
        else:
            refused = False
        seen["absent" if role is None else channel_pb2.Channel.Role.Name(role)] = (
            reads_absent,
            refused,
        )

    assert seen == {
        "absent": (True, True),
        "DISABLED": (True, True),
        "PRIMARY": (False, False),
        "SECONDARY": (False, False),
    }


def test_write_default_channel_rejected_field_restores_snapshot() -> None:
    iface = _FakeIfaceForApply()
    change = SectionChange(
        section="default_channel",
        kind=detect.SectionKind.CHANNEL,
        changes=(
            FieldChange(
                section="default_channel", field="not_a_real_field", current=None, desired=1
            ),
        ),
    )
    pre_call = channel_pb2.ModuleSettings()
    pre_call.CopyFrom(iface.localNode.channels[0].settings.module_settings)

    with pytest.raises(PlanConflictError):
        write_default_channel(iface, change)  # type: ignore[arg-type]

    assert iface.localNode.channels[0].settings.module_settings == pre_call
    assert iface.localNode.written_sections == []


def test_write_default_channel_wraps_every_device_io_error(
    device_io_error: Callable[[], BaseException],
) -> None:
    exc = device_io_error()
    iface = _FakeIfaceRaisesOnWrite(exc)
    change = SectionChange(section="default_channel", kind=detect.SectionKind.CHANNEL, changes=())

    with pytest.raises(ProvisioningError) as exc_info:
        write_default_channel(iface, change)  # type: ignore[arg-type]

    assert exc_info.value.__cause__ is exc


# ---------------------------------------------------------------------------
# A minimal fake interface for write/verify tests.
# ---------------------------------------------------------------------------


def _default_primary_channel() -> channel_pb2.Channel:
    ch = channel_pb2.Channel()
    ch.index = 0
    ch.role = channel_pb2.Channel.Role.PRIMARY
    return ch


class _FakeLocalNode:
    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface
        self.localConfig = localonly_pb2.LocalConfig()
        self.moduleConfig = localonly_pb2.LocalModuleConfig()
        self.channels: list[channel_pb2.Channel] = [_default_primary_channel()]
        self.written_sections: list[str] = []
        self.transaction_calls: list[str] = []
        """Every beginSettingsTransaction()/commitSettingsTransaction() call
        plus every writeConfig() section name, in true chronological order
        -- lets a test assert relative call ORDER, not just that each
        happened. (``written_sections`` stays section-names-only, for
        every existing test that already asserts against it.) A subclass
        that overrides ``writeConfig`` does not necessarily append here
        too -- only the base implementation does."""
        self.begin_error: BaseException | None = None
        """Raised by beginSettingsTransaction() (after recording it) when set."""
        self.commit_error: BaseException | None = None
        """Raised by commitSettingsTransaction() (after recording it) when set."""

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        real_write_config_or_exit(section)
        self.written_sections.append(section)
        self.transaction_calls.append(section)

    def getChannelByChannelIndex(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: N803 -- real method name
    ) -> channel_pb2.Channel | None:
        if 0 <= channelIndex < len(self.channels):
            return self.channels[channelIndex]
        return None

    def writeChannel(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: ARG002, N803 -- real method name
        adminIndex: int = 0,  # noqa: ARG002, N803 -- real method name
    ) -> None:
        self.written_sections.append("default_channel")
        self.transaction_calls.append("default_channel")

    def beginSettingsTransaction(self) -> None:  # noqa: N802 -- real MeshInterface method name
        self.transaction_calls.append("<begin>")
        if self.begin_error is not None:
            raise self.begin_error

    def commitSettingsTransaction(self) -> None:  # noqa: N802 -- real MeshInterface method name
        self.transaction_calls.append("<commit>")
        if self.commit_error is not None:
            raise self.commit_error

    def setOwner(  # noqa: N802 -- real MeshInterface method name
        self,
        long_name: str | None = None,
        short_name: str | None = None,
        is_licensed: bool = False,
        is_unmessagable: bool | None = None,
    ) -> None:
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name
            self._iface.user["isLicensed"] = is_licensed
        if is_unmessagable is not None:
            self._iface.user["isUnmessagable"] = is_unmessagable


_DEFAULT_NODE_NUM: Final = 0xDEADBE01


class _FakeIfaceForApply:
    def __init__(self, node_num: int = _DEFAULT_NODE_NUM) -> None:
        from types import SimpleNamespace

        self.myInfo = SimpleNamespace(my_node_num=node_num)
        self.metadata = SimpleNamespace(hw_model="RAK4631", firmware_version="2.7.11")
        self.user: dict[str, str | bool] = {
            "shortName": "MT00",
            "longName": "Meshtastic MT00",
            "isLicensed": False,
        }
        self.localNode = _FakeLocalNode(self)

    def getMyUser(self) -> dict[str, str | bool]:  # noqa: N802 -- real MeshInterface method name
        return dict(self.user)

    def getPublicKey(self) -> str | None:  # noqa: N802 -- real MeshInterface method name
        raw = bytes(self.localNode.localConfig.security.public_key)
        return base64.b64encode(raw).decode("ascii") if raw else None

    def reopened(self, *, node_num: int | None = None) -> Self:
        """Model a fresh connection to the same device (a plain reconnect).

        Pass ``node_num`` only to model a device that reports a different
        node number after the reconnect (E3 3b); the returned interface
        otherwise carries over this one's current config/user state, the
        same way a real reconnect re-reads what the device actually has.
        """
        fresh = type(self)(node_num=self.myInfo.my_node_num if node_num is None else node_num)
        fresh.localNode.localConfig.CopyFrom(self.localNode.localConfig)
        fresh.localNode.moduleConfig.CopyFrom(self.localNode.moduleConfig)
        fresh.localNode.channels = []
        for ch in self.localNode.channels:
            copy = channel_pb2.Channel()
            copy.CopyFrom(ch)
            fresh.localNode.channels.append(copy)
        fresh.user = dict(self.user)
        return fresh


def test_fake_iface_node_num_is_what_detect_reads() -> None:
    """Guards against ``node_num=`` silently not reaching ``detect``."""
    live = detect.read_live_config(_FakeIfaceForApply(node_num=0xCAFE0002))  # type: ignore[arg-type]
    assert live.node_id.hex == "cafe0002"


def test_fake_local_node_write_config_rejects_what_the_real_library_rejects() -> None:
    iface = _FakeIfaceForApply()

    with pytest.raises(SystemExit):
        iface.localNode.writeConfig("statusmessage")

    assert iface.localNode.written_sections == []
    assert iface.localNode.transaction_calls == []


# ---------------------------------------------------------------------------
# _confirmed_name (verify_plan itself is tested in test_readback.py).
# ---------------------------------------------------------------------------


def _template() -> TemplateConfig:
    return load_template_text("version: 1\n")


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
    assert outcome.exit_code == int(ExitCode.PROVISIONING)
    assert outcome.failures() == (bad_result,)


def test_apply_outcome_dry_run_never_updates_database_even_if_ok() -> None:
    ok_result = WriteResult("device", WriteStatus.SKIPPED, "dry run")
    outcome = ApplyOutcome(node_id=_node_id(), results=(ok_result,), dry_run=True)
    assert outcome.ok is True
    assert outcome.may_update_database is False


def _node_id() -> NodeId:
    return NodeId.from_hex("deadbe01")


# ---------------------------------------------------------------------------
# DeviceSession.reads_back.
# ---------------------------------------------------------------------------


def test_reconnecting_session_reads_back_is_true() -> None:
    session = ReconnectingSession(backend=object())  # type: ignore[arg-type]
    assert session.reads_back is True


def test_in_place_session_reads_back_is_false() -> None:
    session = InPlaceSession(_FakeIfaceForApply())  # type: ignore[arg-type]
    assert session.reads_back is False


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


def test_apply_plan_dry_run_skips_a_rename_too(make_live) -> None:
    """--dry-run's owner/rename preview line was untested.

    Only empty-name-change plans exercised dry_run before this (see
    test_apply_plan_dry_run_never_writes, whose FACTORY plan has no
    desired_short_name/desired_long_name override, so
    plan.name_change.is_empty is always True there and apply_plan's
    `if not plan.name_change.is_empty:` branch never ran).
    """
    template = _template()
    live = make_live(
        template, short_name="be01", long_name="Meshtastic be01", security=make_security(empty=True)
    )
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="MT01",
        desired_long_name="Meshtastic MT01",
    )
    plan = build_plan(inputs)
    assert plan.name_change.is_empty is False
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp, dry_run=True)

    assert outcome.dry_run is True
    assert iface.localNode.written_sections == []
    owner_result = next(r for r in outcome.results if r.section == "owner")
    assert owner_result.status == WriteStatus.SKIPPED
    assert owner_result.message == "dry run"


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
    persisted = persist_result(
        outcome, nodes=nodes, keys=keys, keypair=kp, origin=KeyOrigin.CAPTURED
    )
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
    assert "modem_preset" in lora_result.message and "NOT_A_PRESET" in lora_result.message

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


def test_apply_plan_preserves_is_licensed_when_only_short_name_changes(make_live) -> None:
    """Regression test: the owner-phase write must never reset ``is_licensed``.

    ``Node.setOwner`` defaults ``is_licensed`` to ``False`` whenever
    ``long_name`` is set -- and ``_run_name_phase`` always passes a
    concrete ``long_name`` whenever it runs at all, even when only
    ``short_name`` actually changed. Before the fix, this silently reset
    an already-licensed device's ``is_licensed`` flag to ``False`` on
    every single run that touched the name phase.
    """
    template = _template()
    live = make_live(template, is_licensed=True, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        desired_short_name="MT01",
    )
    plan = build_plan(inputs)
    assert plan.name_change.short_changed is True
    assert plan.name_change.long_changed is False
    assert plan.name_change.desired_is_licensed is True
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    iface.user["isLicensed"] = True
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is True, outcome.describe()
    assert iface.user["isLicensed"] is True


def test_apply_plan_writes_is_unmessagable_when_template_configures_it(make_live) -> None:
    template = _template().model_copy(update={"is_unmessagable": True})
    live = make_live(template, is_unmessagable=None, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert plan.name_change.is_unmessagable_changed is True
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is True, outcome.describe()
    assert iface.user["isUnmessagable"] is True
    is_unmessagable_result = next(r for r in outcome.results if r.field == "is_unmessagable")
    assert is_unmessagable_result.status == WriteStatus.CONFIRMED


class _FakeSessionTracksRefresh:
    """A session whose refresh() swaps in whatever ``on_refresh`` returns.

    Lets a test tell apart "wrote to the pre-reboot interface" from "wrote
    to the post-reboot, refreshed interface" -- or serve a whole sequence
    of distinct interfaces across several refreshes.
    """

    def __init__(
        self,
        first: _FakeIfaceForApply,
        on_refresh: Callable[[int, _FakeIfaceForApply], _FakeIfaceForApply],
    ) -> None:
        self._iface: _FakeIfaceForApply = first
        self._on_refresh = on_refresh
        self.refresh_calls = 0

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    @property
    def reads_back(self) -> bool:
        return True

    def describe(self) -> str:
        return "fake (tracks refresh calls)"

    def refresh(self) -> _FakeIfaceForApply:
        self.refresh_calls += 1
        self._iface = self._on_refresh(self.refresh_calls, self._iface)
        return self._iface


def _serve(
    *ifaces: _FakeIfaceForApply,
) -> Callable[[int, _FakeIfaceForApply], _FakeIfaceForApply]:
    """Build an ``on_refresh`` callback that serves ``ifaces`` in order.

    Refresh *n* (1-based) returns ``ifaces[n - 1]``; once ``ifaces`` is
    exhausted, every later refresh keeps returning the last one.
    """

    def _on_refresh(n: int, _current: _FakeIfaceForApply) -> _FakeIfaceForApply:
        return ifaces[min(n, len(ifaces)) - 1]

    return _on_refresh


def _reopen_same_device(_n: int, cur: _FakeIfaceForApply) -> _FakeIfaceForApply:
    """An ``on_refresh`` callback modelling a plain reconnect to the same device.

    Unlike :func:`_serve`, each call reopens from whatever interface is
    *current* -- so a write made through the previous refresh's interface
    is carried over, the same way a real reconnect re-reads the device's
    actual (persisted) state rather than a blank one.
    """
    return cur.reopened()


class _FakeSessionRefreshFailsAfterFirstCall:
    """A session whose refresh() always raises -- the post-commit, pre-security reconnect case.

    ``reads_back`` is ``True``: under the settings-transaction design,
    this fake is only used with plans that still have a ``security``
    section to write after the (successful) commit, so apply_plan reaches
    the one mid-plan reconnect -- unlike a plan with no ``security``
    section at all, where that property is never consulted.
    """

    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    @property
    def reads_back(self) -> bool:
        return True

    def describe(self) -> str:
        return "fake (refresh fails)"

    def refresh(self) -> _FakeIfaceForApply:
        raise ConnectionBackendError("link dropped after reboot", transport="serial")


def test_apply_plan_writes_every_non_security_section_before_the_one_mid_plan_refresh(
    make_live,
) -> None:
    """A reboot-triggering non-security section causes no refresh of its own any more.

    Under the settings-transaction design, every non-``security`` section
    -- "lora" (which reboots the device) and "device" here -- is written
    (and the transaction committed) against the SAME connection; the only
    mid-plan reconnect happens once, right before ``security``, never
    between individual sections.

    The plan keeps the real security ``SectionChange`` build_plan()
    produced (rather than dropping it, as an earlier version of this test
    did): ``plan.key_plan.regenerate`` is already ``True`` for a FACTORY
    node, and a plan that regenerates without ever writing "security" is
    internally inconsistent -- no real plan does that.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
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
    plan = dataclasses.replace(
        plan, sections=(rebooting_lora_change, later_device_change, security_section)
    )

    reconnects: list[_FakeIfaceForApply] = []

    def _reopen_and_record(n: int, cur: _FakeIfaceForApply) -> _FakeIfaceForApply:
        fresh = _reopen_same_device(n, cur)
        reconnects.append(fresh)
        return fresh

    first_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, _reopen_and_record)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    # Both non-security sections land on the SAME connection, in order,
    # before any refresh -- the transaction only commits once the loop
    # over them finishes.
    assert first_iface.localNode.written_sections == ["lora", "device"]
    assert first_iface.localNode.transaction_calls == ["<begin>", "lora", "device", "<commit>"]

    # Exactly one mid-plan refresh (right before "security"), plus the
    # unconditional final-verify refresh at the end of apply_plan.
    assert session.refresh_calls == 2
    mid_plan_iface, final_iface = reconnects
    assert mid_plan_iface.localNode.written_sections == ["security"]
    # The final verify reconnect is itself a fresh reopen -- it never
    # writes anything, only re-reads what was already persisted.
    assert final_iface.localNode.written_sections == []

    assert outcome.ok is True, outcome.describe()
    assert outcome.may_update_database is True
    for result in outcome.results:
        assert result.status == WriteStatus.CONFIRMED, result

    assert outcome.record is not None
    assert outcome.record.node_id == plan.node_id.hex
    assert outcome.public_key_fingerprint == redact.fingerprint(kp.public)


def test_apply_plan_mid_loop_reconnect_to_a_device_that_lost_the_pre_reboot_write_is_uncertain(
    make_live,
) -> None:
    """A reboot that drops the pre-reboot write must read back UNCONFIRMED, not a false CONFIRMED.

    Companion to the "successful" mid-loop reconnect test above: this
    models a genuine data loss across the reboot (the reopened device is
    missing the "lora" section it was written just before reconnecting),
    which the fake must be able to express now that "persisted" is a
    real, distinct state from "what the host staged".
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
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
    plan = dataclasses.replace(
        plan, sections=(rebooting_lora_change, later_device_change, security_section)
    )

    first_iface = _FakeIfaceForApply()
    lost_iface = first_iface.reopened()
    lost_iface.localNode.localConfig.ClearField("lora")
    session = _FakeSessionTracksRefresh(first_iface, _serve(lost_iface))
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    hop_limit_result = next(r for r in outcome.results if r.field == "hop_limit")
    assert hop_limit_result.status == WriteStatus.UNCONFIRMED
    assert outcome.ok is False
    assert outcome.may_update_database is False


def test_apply_plan_reports_uncertain_when_the_post_commit_reconnect_fails(make_live) -> None:
    """The one mid-plan reconnect (after committing, before `security`) can also fail.

    All non-security sections are written and the transaction committed
    first -- only the refresh right before `security` can fail here;
    there is no longer a reconnect between individual sections.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
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
    plan = dataclasses.replace(
        plan, sections=(rebooting_lora_change, later_device_change, security_section)
    )

    iface = _FakeIfaceForApply()
    session = _FakeSessionRefreshFailsAfterFirstCall(iface)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert outcome.verified is True
    assert outcome.ok is False
    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "reconnect" in verify_result.message
    # Both non-security sections are already committed to the device by
    # the time the (failing) mid-plan reconnect is attempted.
    assert iface.localNode.written_sections == ["lora", "device"]
    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED
    assert outcome.security_attempted is False


class _FakeSessionRefreshFailsWithHintAfterFirstCall:
    """Post-commit, pre-security reconnect-failure variant whose exception carries a hint.

    See :class:`_FakeSessionRefreshFailsAfterFirstCall` for why
    ``reads_back`` is ``True`` here.
    """

    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    @property
    def reads_back(self) -> bool:
        return True

    def describe(self) -> str:
        return "fake (refresh fails, with hint)"

    def refresh(self) -> _FakeIfaceForApply:
        raise ConnectionFailedError(
            "link dropped after reboot", hint="check the cable", transport="serial"
        )


def test_apply_plan_post_commit_reconnect_failure_skips_security_and_keeps_the_hint(
    make_live,
) -> None:
    """The post-commit, pre-security reconnect-failure arm must carry the cause/hint and SKIP it.

    Companion to the sibling identity-check arms just below it (mismatch
    and unreadable-identity), which already extend `results` with a
    SKIPPED entry for `security` and set `security_attempted=False` --
    this arm must do the same instead of silently dropping it.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
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
    plan = dataclasses.replace(
        plan, sections=(rebooting_lora_change, later_device_change, security_section)
    )

    iface = _FakeIfaceForApply()
    session = _FakeSessionRefreshFailsWithHintAfterFirstCall(iface)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "link dropped after reboot" in verify_result.message
    assert "check the cable" in verify_result.message

    # Both non-security sections were already committed before the
    # (failing) mid-plan reconnect was attempted -- only `security` is
    # skipped.
    assert iface.localNode.written_sections == ["lora", "device"]
    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED

    assert outcome.security_attempted is False


# ---------------------------------------------------------------------------
# apply_plan reconnect identity check (E3) -- a mid-plan or final reconnect
# that answers as a different node must be an unconditional hard stop.
# ---------------------------------------------------------------------------


class _FakeIfaceUnreadableIdentity(_FakeIfaceForApply):
    """Models a reconnect whose identity cannot be read at all (myInfo=None, getMyNodeInfo()={})."""

    def __init__(self) -> None:
        super().__init__()
        self.myInfo = None  # type: ignore[assignment]

    def getMyNodeInfo(self) -> dict[str, int]:  # noqa: N802 -- real MeshInterface method name
        return {}


def _factory_plan_with_reboot_then_security(make_live: Callable[..., object]) -> ChangePlan:
    """Build a FACTORY plan with an explicit reboot section before security.

    Shared by the mid-plan identity tests below -- same shape as
    ``test_apply_plan_reconnects_mid_loop_after_a_reboot_before_writing_later_sections``.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
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
    return dataclasses.replace(
        plan, sections=(rebooting_lora_change, later_device_change, security_section)
    )


def test_apply_plan_mid_plan_reconnect_to_a_different_node_is_a_hard_stop(make_live) -> None:
    """E3 headline: an accidental device swap during the post-commit reconnect never sends security.

    Every non-security section is written to -- and the transaction
    committed on -- the ORIGINAL device before the one mid-plan
    reconnect (right before `security`) happens, so a swap detected at
    that reconnect means `lora`/`device` already landed on the real
    device; `security` -- the freshly generated keypair and admin keys --
    is the one that must never reach the swapped-in impostor, and the
    outcome can never be persisted.
    """
    plan = _factory_plan_with_reboot_then_security(make_live)
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    impostor = _FakeIfaceForApply(node_num=0xCAFE0002)
    session = _FakeSessionTracksRefresh(first_iface, _serve(impostor))
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert first_iface.localNode.written_sections == ["lora", "device"]
    assert impostor.localNode.written_sections == []
    assert bytes(impostor.localNode.localConfig.security.private_key) != kp.private.reveal()

    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "!cafe0002" in verify_result.message
    assert "!deadbe01" in verify_result.message

    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED
    assert "different node" in security_result.message

    assert outcome.may_update_database is False
    assert outcome.record is None
    assert outcome.security_attempted is False
    assert outcome.exit_code == int(ExitCode.PROVISIONING)


def test_apply_plan_mid_plan_reconnect_with_unreadable_identity_is_a_hard_stop(make_live) -> None:
    """An identity that cannot be confirmed after a reconnect must stop too -- not just a mismatch.

    An unknown identity must not receive key material either: treating
    "could not read the id" as "assume it's fine" would defeat the whole
    check.
    """
    plan = _factory_plan_with_reboot_then_security(make_live)
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    unreadable = _FakeIfaceUnreadableIdentity()
    session = _FakeSessionTracksRefresh(first_iface, _serve(unreadable))
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "could not confirm the node's identity" in verify_result.message
    assert unreadable.localNode.written_sections == []
    assert outcome.security_attempted is False
    assert outcome.may_update_database is False
    assert outcome.record is None


def test_apply_plan_mid_plan_reconnect_with_an_invalid_node_id_is_a_hard_stop(make_live) -> None:
    """A reconnect reporting a node number that is not a node id stops like an unreadable one.

    ``read_node_id`` now maps the ``NodeIdError`` to a ``DetectionError``,
    which this check already catches; before, it escaped ``apply_plan``
    altogether, with no UNCERTAIN report for the sections already written.
    """
    plan = _factory_plan_with_reboot_then_security(make_live)
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    invalid = _FakeIfaceForApply(node_num=2**32)
    session = _FakeSessionTracksRefresh(first_iface, _serve(invalid))
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "could not confirm the node's identity" in verify_result.message
    assert first_iface.localNode.written_sections == ["lora", "device"]
    assert invalid.localNode.written_sections == []
    assert outcome.security_attempted is False
    assert outcome.may_update_database is False
    assert outcome.exit_code == int(ExitCode.PROVISIONING)


def test_apply_plan_final_verify_reconnect_to_a_different_node_never_runs_verify_plan(
    make_live,
) -> None:
    """A final-verify-only swap must stop before `verify_plan`, even with a matching config.

    The impostor's `device.role` is set to exactly what the plan wants,
    proving the stop fires because of the identity check, not because of
    an unrelated value mismatch `verify_plan` would have reported anyway.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    plan = dataclasses.replace(plan, sections=(device_change,), key_plan=KeyPlan())

    first_iface = _FakeIfaceForApply()
    impostor = first_iface.reopened(node_num=0xCAFE0002)
    impostor.localNode.localConfig.device.role = 2  # ROUTER -- matches the plan's intent.
    session = _FakeSessionTracksRefresh(first_iface, _serve(impostor))
    outcome = apply_plan(plan, session, keypair=None)  # type: ignore[arg-type]

    assert not any(r.status == WriteStatus.CONFIRMED for r in outcome.results)
    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "!cafe0002" in verify_result.message
    assert outcome.record is None
    assert outcome.may_update_database is False


def test_apply_plan_final_verify_node_renumber_with_matching_keypair_gets_a_distinct_message(
    make_live,
) -> None:
    """E3 3b: a final reconnect to a new node number holding this run's OWN keypair is not a swap.

    Diagnostic only -- it still refuses to persist, since re-keying a
    database row to a new node id automatically is out of scope.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
    plan = dataclasses.replace(plan, sections=(security_section,))
    assert plan.key_plan.regenerate is True
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    renumbered = first_iface.reopened(node_num=0xCAFE0002)
    renumbered.localNode.localConfig.security.private_key = kp.private.reveal()
    renumbered.localNode.localConfig.security.public_key = kp.public
    session = _FakeSessionTracksRefresh(first_iface, _serve(renumbered))
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert "node number appears to have changed" in verify_result.message
    assert "firmware 2.8" in verify_result.message
    assert "database was NOT updated" in verify_result.message
    # Must stay distinguishable from the ordinary accidental-swap message.
    assert not verify_result.message.startswith("reconnected to a different node")
    assert outcome.may_update_database is False
    assert outcome.record is None


def test_apply_plan_final_verify_node_renumber_without_matching_keypair_is_an_ordinary_mismatch(
    make_live,
) -> None:
    """3b must not fire just because the node number changed -- only when the keypair also matches.

    Guards against a too-loose 3b condition swallowing genuine swaps: a
    device that reports a new number but a DIFFERENT (or no) private key
    is an ordinary mismatch, not a renumber.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
    plan = dataclasses.replace(plan, sections=(security_section,))
    kp = generate_keypair()
    other_kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    renumbered = first_iface.reopened(node_num=0xCAFE0002)
    renumbered.localNode.localConfig.security.private_key = other_kp.private.reveal()
    renumbered.localNode.localConfig.security.public_key = other_kp.public
    session = _FakeSessionTracksRefresh(first_iface, _serve(renumbered))
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    verify_result = next(r for r in outcome.results if r.section == "<verify>")
    assert verify_result.status == WriteStatus.FAILED
    assert verify_result.message.startswith("reconnected to a different node")
    assert "node number appears to have changed" not in verify_result.message


def test_apply_plan_same_node_reconnect_is_unaffected_by_the_identity_check(make_live) -> None:
    """Unchanged behavior: a plain same-device reconnect never trips the new check."""
    plan = _factory_plan_with_reboot_then_security(make_live)
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, _reopen_same_device)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert outcome.ok is True, outcome.describe()
    assert outcome.may_update_database is True
    assert not any(
        r.section == "<verify>" and r.status == WriteStatus.FAILED for r in outcome.results
    )


def test_apply_plan_calls_on_reconnect_before_each_refresh(make_live) -> None:
    """3c: on_reconnect fires once per refresh, including the mid-plan one."""
    plan = _factory_plan_with_reboot_then_security(make_live)
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, _reopen_same_device)
    calls: list[int] = []
    outcome = apply_plan(
        plan,
        session,
        keypair=kp,  # type: ignore[arg-type]
        on_reconnect=lambda: calls.append(session.refresh_calls),
    )

    assert outcome.ok is True, outcome.describe()
    # One call recorded right before each of the two refreshes (mid-plan,
    # then final) -- refresh_calls is 0 at each recorded moment, since the
    # callback runs strictly before refresh() increments it.
    assert calls == [0, 1]
    assert session.refresh_calls == 2


# ---------------------------------------------------------------------------
# The settings transaction (D2 Option A, refined by N3/N5): every
# non-security section (plus the name phase) is written inside one
# beginSettingsTransaction()/commitSettingsTransaction() pair.
# ---------------------------------------------------------------------------


def test_apply_plan_begins_transaction_before_first_write_and_commits_before_security(
    make_live,
) -> None:
    """Order, not just occurrence: begin precedes the first write, commit precedes security.

    A reconnecting session defers `security` to its own write, after the
    transaction commits and a fresh reconnect -- so `security` landing on
    a DIFFERENT (reopened) interface than the one `lora` and the commit
    used is itself proof that the commit finished first.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, security_section))
    kp = generate_keypair()

    reconnects: list[_FakeIfaceForApply] = []

    def _reopen_and_record(n: int, cur: _FakeIfaceForApply) -> _FakeIfaceForApply:
        fresh = _reopen_same_device(n, cur)
        reconnects.append(fresh)
        return fresh

    first_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, _reopen_and_record)
    sleep_calls: list[float] = []
    on_reconnect_calls: list[int] = []
    outcome = apply_plan(
        plan,
        session,  # type: ignore[arg-type]
        keypair=kp,
        sleep=sleep_calls.append,
        on_reconnect=lambda: on_reconnect_calls.append(session.refresh_calls),
    )

    assert outcome.ok is True, outcome.describe()
    assert first_iface.localNode.transaction_calls == ["<begin>", "lora", "<commit>"]
    assert "security" not in first_iface.localNode.written_sections

    assert session.refresh_calls == 2
    assert on_reconnect_calls == [0, 1]
    assert sleep_calls == [DEFAULT_SETTLE_SECONDS, DEFAULT_SETTLE_SECONDS]
    mid_plan_iface, _final_iface = reconnects
    assert mid_plan_iface.localNode.written_sections == ["security"]


def test_apply_plan_default_channel_writes_before_security_reconnecting(make_live) -> None:
    """default_channel shares security's post-commit reconnect and lands right before it."""
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
    security_section = next(s for s in plan.sections if s.section == "security")
    channel_section = next(s for s in plan.sections if s.section == "default_channel")
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, channel_section, security_section))
    kp = generate_keypair()

    reconnects: list[_FakeIfaceForApply] = []

    def _reopen_and_record(n: int, cur: _FakeIfaceForApply) -> _FakeIfaceForApply:
        fresh = _reopen_same_device(n, cur)
        reconnects.append(fresh)
        return fresh

    first_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, _reopen_and_record)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert outcome.ok is True, outcome.describe()
    assert first_iface.localNode.transaction_calls == ["<begin>", "lora", "<commit>"]
    assert "default_channel" not in first_iface.localNode.written_sections
    assert "security" not in first_iface.localNode.written_sections

    mid_plan_iface, _final_iface = reconnects
    assert mid_plan_iface.localNode.written_sections == ["default_channel", "security"]


def test_apply_plan_default_channel_failure_skips_security_reconnecting(make_live) -> None:
    """A default_channel write failure cascades into security being SKIPPED."""
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
    security_section = next(s for s in plan.sections if s.section == "security")
    channel_section = next(s for s in plan.sections if s.section == "default_channel")
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, channel_section, security_section))
    kp = generate_keypair()

    first_iface = _FakeIfaceForApply()
    failing_iface = _FakeIfaceRaisesOnWrite(OSError(errno.EIO, "fake I/O error"))
    session = _FakeSessionTracksRefresh(first_iface, lambda _n, _cur: failing_iface)
    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    channel_result = next(r for r in outcome.results if r.section == "default_channel")
    assert channel_result.status == WriteStatus.FAILED
    assert "may or may not" in channel_result.message

    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED
    assert "default_channel" in security_result.message

    assert outcome.security_attempted is False
    assert outcome.may_update_database is False


def _lora_then_security_plan(make_live: Callable[..., object]) -> ChangePlan:
    """A FACTORY plan with one lora change and the plan's own (deferred) security section."""
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    plan = build_plan(
        PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    )
    security_section = next(s for s in plan.sections if s.section == "security")
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    return dataclasses.replace(plan, sections=(lora_change, security_section))


def test_apply_plan_deferred_security_write_failure_is_marked_attempted(make_live) -> None:
    """A deferred security write that raises may have reached the device: it counts as attempted.

    ``security_attempted`` is what keeps the CLI from deleting the pending
    keypair file -- the regenerated key may now be on the device.
    """
    plan = _lora_then_security_plan(make_live)
    first_iface = _FakeIfaceForApply()
    failing_iface = _FakeIfaceRaisesOnWrite(OSError(errno.EIO, "fake I/O error"))
    session = _FakeSessionTracksRefresh(first_iface, lambda _n, _cur: failing_iface)

    outcome = apply_plan(plan, session, keypair=generate_keypair())  # type: ignore[arg-type]

    # Security is written after the commit, on the reconnected interface.
    assert first_iface.localNode.transaction_calls[-1] == "<commit>"
    assert "security" not in first_iface.localNode.written_sections
    assert failing_iface.localNode.written_sections == ["security"]
    security_result = next(
        r for r in outcome.results if r.section == "security" and r.field is None
    )
    assert security_result.status == WriteStatus.FAILED
    assert "may or may not" in security_result.message
    assert outcome.security_attempted is True
    assert outcome.may_update_database is False


def test_apply_plan_deferred_security_pre_io_failure_is_not_marked_attempted(
    make_live, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deferred security write refused before any I/O never left the host: not attempted."""
    plan = _lora_then_security_plan(make_live)
    real_write_section = apply_module.write_section

    def _refuse_security(iface: object, change: SectionChange, **kwargs: object) -> None:
        if change.section == "security":
            raise PlanConflictError("simulated pre-I/O refusal", field="security.is_managed")
        real_write_section(iface, change, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(apply_module, "write_section", _refuse_security)
    first_iface = _FakeIfaceForApply()
    refreshed: list[_FakeIfaceForApply] = []

    def _on_refresh(_n: int, cur: _FakeIfaceForApply) -> _FakeIfaceForApply:
        refreshed.append(cur.reopened())
        return refreshed[-1]

    session = _FakeSessionTracksRefresh(first_iface, _on_refresh)

    outcome = apply_plan(plan, session, keypair=generate_keypair())  # type: ignore[arg-type]

    assert first_iface.localNode.written_sections == ["lora"]
    assert all("security" not in iface.localNode.written_sections for iface in refreshed)
    security_result = next(
        r for r in outcome.results if r.section == "security" and r.field is None
    )
    assert security_result.status == WriteStatus.FAILED
    assert security_result.message.startswith("not written: ")
    assert "simulated pre-I/O refusal" in security_result.message
    assert outcome.security_attempted is False
    # Not attempted, so the final verify never checks security fields either.
    assert not any(r.section == "security" and r.field is not None for r in outcome.results)
    assert outcome.may_update_database is False


def test_apply_plan_default_channel_in_place_lands_before_security(make_live) -> None:
    """Under --no-reconnect, default_channel writes in its natural order, no extra reconnect."""
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
    security_section = next(s for s in plan.sections if s.section == "security")
    channel_section = next(s for s in plan.sections if s.section == "default_channel")
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, channel_section, security_section))
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is True, outcome.describe()
    assert iface.localNode.transaction_calls == [
        "<begin>",
        "lora",
        "default_channel",
        "security",
        "<commit>",
    ]


def test_apply_plan_commits_transaction_even_when_a_mid_loop_section_fails(make_live) -> None:
    """A mid-loop non-security failure must not skip the finally-driven commit."""
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")

    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, device_change, security_section))
    kp = generate_keypair()

    iface = _FakeIfaceFailsOnSections(
        fail_sections=frozenset({"lora"}), exc=OSError(errno.EIO, "fake I/O error")
    )
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert iface.localNode.transaction_calls[0] == "<begin>"
    assert iface.localNode.transaction_calls[-1] == "<commit>"
    assert "<commit>" in iface.localNode.transaction_calls

    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED
    assert outcome.security_attempted is False
    assert outcome.may_update_database is False


def test_apply_plan_transaction_scope_security_only_vs_in_place_with_sections(make_live) -> None:
    """A security-only plan opens no transaction; an in-place session folds security into the one.

    N3: under ``--no-reconnect`` (``InPlaceSession``), ``security`` is
    written INSIDE the same transaction as every other section, committed
    exactly once, at the very end -- never split into its own separate
    write/commit.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    assert [s.section for s in plan.sections] == ["security"]
    security_section = plan.sections[0]

    security_only_iface = _FakeIfaceForApply()
    kp = generate_keypair()
    outcome = apply_plan(
        plan,
        InPlaceSession(security_only_iface),
        keypair=kp,  # type: ignore[arg-type]
    )
    assert outcome.ok is True, outcome.describe()
    assert security_only_iface.localNode.transaction_calls == ["security"]

    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    multi_section_plan = dataclasses.replace(plan, sections=(lora_change, security_section))
    multi_iface = _FakeIfaceForApply()
    kp2 = generate_keypair()
    outcome2 = apply_plan(
        multi_section_plan,
        InPlaceSession(multi_iface),
        keypair=kp2,  # type: ignore[arg-type]
    )

    assert outcome2.ok is True, outcome2.describe()
    assert multi_iface.localNode.transaction_calls == ["<begin>", "lora", "security", "<commit>"]
    assert multi_iface.localNode.transaction_calls.count("<commit>") == 1


def test_apply_plan_post_commit_reconnect_only_happens_when_security_remains(make_live) -> None:
    """The post-commit settle+refresh+identity-check runs only when `security` is still to write.

    Positive: with `security` present on a reconnecting session, exactly
    one extra refresh happens (between the commit and the security
    write), on top of the unconditional final verify. N5: with only
    non-security sections in the plan, that whole sequence is skipped --
    the only refresh left is the unconditional final verify.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    security_section = next(s for s in plan.sections if s.section == "security")
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )

    with_security_plan = dataclasses.replace(plan, sections=(lora_change, security_section))
    first_iface = _FakeIfaceForApply()
    session = _FakeSessionTracksRefresh(first_iface, _reopen_same_device)
    kp = generate_keypair()
    outcome = apply_plan(with_security_plan, session, keypair=kp)  # type: ignore[arg-type]
    assert outcome.ok is True, outcome.describe()
    assert session.refresh_calls == 2

    no_security_plan = dataclasses.replace(plan, sections=(lora_change,), key_plan=KeyPlan())
    second_iface = _FakeIfaceForApply()
    second_session = _FakeSessionTracksRefresh(second_iface, _reopen_same_device)
    outcome2 = apply_plan(no_security_plan, second_session, keypair=None)  # type: ignore[arg-type]
    assert outcome2.ok is True, outcome2.describe()
    # Only the unconditional final-verify refresh -- no mid-plan one, since
    # there is no `security` section left to protect it for.
    assert second_session.refresh_calls == 1


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
        apply_session_module._RECONNECT_BACKOFF * 1,
        apply_session_module._RECONNECT_BACKOFF * 2,
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
        apply_session_module._RECONNECT_BACKOFF * 1,
        apply_session_module._RECONNECT_BACKOFF * 2,
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
    assert verify_results[0].message.startswith("Could not reconnect to verify the writes")


class _RefreshFailsWithHintSession:
    """Final-verify reconnect-failure variant whose exception carries an actionable hint."""

    def __init__(self, iface: _FakeIfaceForApply) -> None:
        self._iface = iface

    @property
    def interface(self) -> _FakeIfaceForApply:
        return self._iface

    def describe(self) -> str:
        return "fake (refresh always fails, with hint)"

    def refresh(self) -> _FakeIfaceForApply:
        raise ConnectionFailedError("link dropped", hint="check the cable", transport="serial")


def test_apply_plan_final_verify_reconnect_failure_keeps_the_cause_and_hint(
    tmp_path, make_live
) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    iface = _FakeIfaceForApply()
    session = _RefreshFailsWithHintSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    verify_results = [r for r in outcome.results if r.section == "<verify>"]
    assert len(verify_results) == 1
    assert verify_results[0].status == WriteStatus.FAILED
    assert verify_results[0].message.startswith("Could not reconnect to verify the writes")
    assert "link dropped" in verify_results[0].message
    assert "check the cable" in verify_results[0].message


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

    def getMyUser(self) -> dict[str, str | bool]:  # noqa: N802 -- real MeshInterface method name
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
        is_licensed: bool = False,
        is_unmessagable: bool | None = None,
    ) -> None:
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name[:20]
            self._iface.user["isLicensed"] = is_licensed
        if is_unmessagable is not None:
            self._iface.user["isUnmessagable"] = is_unmessagable


class _FakeIfaceTruncatesLongName(_FakeIfaceForApply):
    """An interface whose firmware truncates every long_name write to 20 bytes."""

    def __init__(self, node_num: int = _DEFAULT_NODE_NUM) -> None:
        super().__init__(node_num)
        self.localNode = _FakeLocalNodeTruncatesLongName(self)


class _FakeLocalNodeRaisesOnSetOwner(_FakeLocalNode):
    """Simulates a device/communication failure during the owner (name) write."""

    def __init__(self, iface: _FakeIfaceForApply, exc: BaseException) -> None:
        super().__init__(iface)
        self._exc = exc

    def setOwner(self, **_kw: object) -> None:  # noqa: N802 -- real MeshInterface method name
        raise self._exc


class _FakeIfaceRaisesOnSetOwner(_FakeIfaceForApply):
    """An interface whose owner (name) write always raises ``exc``."""

    def __init__(self, exc: BaseException | None = None, node_num: int = _DEFAULT_NODE_NUM) -> None:
        super().__init__(node_num)
        resolved_exc = exc if exc is not None else OSError("serial write timed out")
        self.localNode = _FakeLocalNodeRaisesOnSetOwner(self, resolved_exc)


class _FakeLocalNodeRaisesOnWrite(_FakeLocalNode):
    """Simulates a device/communication failure during a config section write."""

    def __init__(self, iface: _FakeIfaceForApply, exc: BaseException) -> None:
        super().__init__(iface)
        self._exc = exc

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        real_write_config_or_exit(section)
        self.written_sections.append(section)
        raise self._exc

    def writeChannel(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: ARG002, N803 -- real method name
        adminIndex: int = 0,  # noqa: ARG002, N803 -- real method name
    ) -> None:
        self.written_sections.append("default_channel")
        raise self._exc


class _FakeIfaceRaisesOnWrite(_FakeIfaceForApply):
    """An interface whose config section write always raises ``exc``."""

    def __init__(self, exc: BaseException, node_num: int = _DEFAULT_NODE_NUM) -> None:
        super().__init__(node_num)
        self.localNode = _FakeLocalNodeRaisesOnWrite(self, exc)


class _FakeLocalNodeFailsOnSections(_FakeLocalNode):
    """Simulates a device I/O failure for specific sections only; others succeed."""

    def __init__(
        self,
        iface: _FakeIfaceForApply,
        *,
        fail_sections: frozenset[str],
        exc: BaseException | None = None,
    ) -> None:
        super().__init__(iface)
        self._fail_sections = fail_sections
        self._exc = exc

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        real_write_config_or_exit(section)
        self.written_sections.append(section)
        if section in self._fail_sections:
            raise (
                self._exc if self._exc is not None else OSError(errno.EIO, "simulated I/O failure")
            )

    def writeChannel(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: ARG002, N803 -- real method name
        adminIndex: int = 0,  # noqa: ARG002, N803 -- real method name
    ) -> None:
        self.written_sections.append("default_channel")
        if "default_channel" in self._fail_sections:
            raise (
                self._exc if self._exc is not None else OSError(errno.EIO, "simulated I/O failure")
            )


class _FakeIfaceFailsOnSections(_FakeIfaceForApply):
    """An interface whose config section write raises only for ``fail_sections``."""

    def __init__(
        self,
        *,
        fail_sections: frozenset[str],
        exc: BaseException | None = None,
        node_num: int = _DEFAULT_NODE_NUM,
    ) -> None:
        super().__init__(node_num)
        self.localNode = _FakeLocalNodeFailsOnSections(self, fail_sections=fail_sections, exc=exc)


# ---------------------------------------------------------------------------
# Device I/O exceptions besides OSError/RuntimeError (BLE, MeshInterface, ...)
# must be caught and converted, never escape as a raw traceback.
# ---------------------------------------------------------------------------


def test_write_section_wraps_every_device_io_error(
    device_io_error: Callable[[], BaseException],
) -> None:
    exc = device_io_error()
    iface = _FakeIfaceRaisesOnWrite(exc)
    change = SectionChange(section="device", kind=detect.SectionKind.CONFIG, changes=())

    with pytest.raises(ProvisioningError) as exc_info:
        write_section(iface, change)  # type: ignore[arg-type]

    assert exc_info.value.__cause__ is exc


def test_write_section_does_not_swallow_a_programming_error() -> None:
    """Pins the module's "no broad except" discipline against a future regression."""
    iface = _FakeIfaceRaisesOnWrite(ZeroDivisionError("boom"))
    change = SectionChange(section="device", kind=detect.SectionKind.CONFIG, changes=())

    with pytest.raises(ZeroDivisionError):
        write_section(iface, change)  # type: ignore[arg-type]


def test_apply_plan_owner_write_failure_reports_failed_for_every_device_io_error(
    make_live, device_io_error: Callable[[], BaseException]
) -> None:
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

    iface = _FakeIfaceRaisesOnSetOwner(exc=device_io_error())
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert outcome.ok is False
    owner_result = next(r for r in outcome.results if r.section == "owner")
    assert owner_result.status == WriteStatus.FAILED
    assert "Failed to set owner" in owner_result.message


# ---------------------------------------------------------------------------
# Stop-on-first-failure: a mid-plan failure must never let a later section
# (security in particular) be written.
# ---------------------------------------------------------------------------


def _lockdown_regenerate_plan(make_live, make_admin_key) -> ChangePlan:
    """Build a real plan on a factory node with lockdown authorized and a regenerated key."""
    admin = make_admin_key("ADMIN1", has_private=True, audit_ok=True)
    base_template = _template()
    template = base_template.model_copy(
        update={
            "admin_nodes": ("ADMIN1",),
            "security": base_template.security.model_copy(update={"is_managed": True}),
        }
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=None,
        state=detect.NodeState.FACTORY,
        admin_keys=(admin,),
        allow_lockdown=True,
    )
    return build_plan(inputs)


def test_apply_plan_lockdown_write_failure_never_writes_security(make_live, make_admin_key) -> None:
    """The review's headline probe: an early I/O failure must withhold ``security`` too."""
    plan = _lockdown_regenerate_plan(make_live, make_admin_key)
    security_section = plan.section("security")
    assert security_section is not None
    assert plan.key_plan.regenerate is True

    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, security_section))
    kp = generate_keypair()

    iface = _FakeIfaceFailsOnSections(
        fail_sections=frozenset({"lora"}), exc=OSError(errno.EIO, "fake I/O error")
    )
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert iface.localNode.written_sections == ["lora"]
    assert "security" not in iface.localNode.written_sections
    assert iface.localNode.localConfig.security.is_managed is False
    assert bytes(iface.localNode.localConfig.security.private_key) != kp.private.reveal()

    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED
    assert "not written" in security_result.message

    lora_result = next(r for r in outcome.results if r.section == "lora")
    assert lora_result.status == WriteStatus.FAILED
    assert "may or may not" in lora_result.message

    assert outcome.exit_code == ExitCode.PROVISIONING
    assert outcome.may_update_database is False
    assert outcome.security_attempted is False
    assert outcome.public_key_fingerprint is None


def test_apply_plan_an_io_failure_skips_every_later_section_not_only_security(
    make_live, make_admin_key
) -> None:
    """A non-security section between the failure and security must also be skipped.

    Pins "stop everything" against a future narrowing to "skip security
    only": ``device`` sits between the failing ``lora`` write and
    ``security`` here, and it must never be attempted either.
    """
    plan = _lockdown_regenerate_plan(make_live, make_admin_key)
    security_section = plan.section("security")
    assert security_section is not None

    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, device_change, security_section))
    kp = generate_keypair()

    iface = _FakeIfaceFailsOnSections(
        fail_sections=frozenset({"lora"}), exc=OSError(errno.EIO, "fake I/O error")
    )
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert iface.localNode.written_sections == ["lora"]

    device_result = next(r for r in outcome.results if r.section == "device")
    assert device_result.status == WriteStatus.SKIPPED
    assert "not written" in device_result.message

    security_result = next(r for r in outcome.results if r.section == "security")
    assert security_result.status == WriteStatus.SKIPPED
    assert "not written" in security_result.message

    assert outcome.security_attempted is False
    assert outcome.may_update_database is False


def test_apply_plan_owner_write_failure_stops_every_section(make_live) -> None:
    """A name-phase failure must also withhold every section, not only security."""
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
    security_section = plan.section("security")
    assert security_section is not None
    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change, security_section))
    kp = generate_keypair()

    iface = _FakeIfaceRaisesOnSetOwner()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    assert iface.localNode.written_sections == []
    for change in plan.sections:
        result = next(r for r in outcome.results if r.section == change.section)
        assert result.status == WriteStatus.SKIPPED
    assert outcome.security_attempted is False
    assert outcome.may_update_database is False


def test_apply_plan_pre_io_failure_is_labelled_not_written_and_not_verified(make_live) -> None:
    """A pre-I/O (enum-mapping) failure must not be verified, and must stop later sections."""
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
    good_device_change = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    plan = dataclasses.replace(plan, sections=(bad_lora_change, good_device_change))

    iface = _FakeIfaceForApply()
    pre_call_lora = localonly_pb2.LocalConfig()
    pre_call_lora.CopyFrom(iface.localNode.localConfig)
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    lora_result = next(r for r in outcome.results if r.section == "lora")
    assert lora_result.status == WriteStatus.FAILED
    assert lora_result.message.startswith("not written")

    device_result = next(r for r in outcome.results if r.section == "device")
    assert device_result.status == WriteStatus.SKIPPED

    # lora was never sent to the device: writeConfig was never even called.
    assert "lora" not in iface.localNode.written_sections
    assert iface.localNode.localConfig.lora == pre_call_lora.lora


def test_apply_plan_in_place_no_contradictory_confirmed_after_a_failed_write(make_live) -> None:
    """The in-place-session contradiction the review found: no false 'confirmed'.

    Before the snapshot-restore fix, a failed write left the in-memory
    section mutated, so an in-place (``--no-reconnect``) read-back of the
    *same* interface would show that section's fields as CONFIRMED right
    next to the section itself being FAILED.
    """
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    plan = build_plan(inputs)
    kp = generate_keypair()

    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    plan = dataclasses.replace(plan, sections=(lora_change,))

    iface = _FakeIfaceFailsOnSections(fail_sections=frozenset({"lora"}))
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    for result in outcome.results:
        if result.section == "lora" and result.field is not None:
            assert result.status != WriteStatus.CONFIRMED, result


def test_apply_plan_adopt_key_still_verified_when_security_is_skipped(
    make_live, keypair_factory
) -> None:
    """An adopt-device-key plan's key material is still verified after an earlier failure.

    ``_verify_key_material`` for ``adopt_device_key`` checks that the
    device's pre-existing key survived this run's writes -- that check is
    independent of whether this run's own security write happened.
    """
    kp = keypair_factory()
    other_kp = keypair_factory()
    plan = adopt_device_key_plan(make_live, kp, other_kp)

    lora_change = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="region", current="UNSET", desired="EU_868"),),
    )
    security_section = plan.section("security")
    sections = (lora_change, *(() if security_section is None else (security_section,)))
    plan = dataclasses.replace(plan, sections=sections)

    iface = _FakeIfaceFailsOnSections(
        fail_sections=frozenset({"lora"}), exc=OSError(errno.EIO, "fake I/O error")
    )
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    session = InPlaceSession(iface)  # type: ignore[arg-type]
    outcome = apply_plan(plan, session, keypair=kp)

    key_result = next(r for r in outcome.results if r.field == "public_key")
    assert key_result.status == WriteStatus.CONFIRMED
    assert outcome.security_attempted is False


# ---------------------------------------------------------------------------
# Early exits (Round 39 E39-1/F4): every part of the plan that never reached
# the device is recorded SKIPPED, and nothing that may have reached it is.
# ---------------------------------------------------------------------------


def _early_exit_plan(make_live: Callable[..., object]) -> ChangePlan:
    """A FACTORY plan with an owner change, lora, device, default_channel and security."""
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
    lora = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="hop_limit", current=3, desired=5),),
    )
    device = SectionChange(
        section="device",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="device", field="role", current="CLIENT", desired="ROUTER"),),
    )
    channel = next(s for s in plan.sections if s.section == "default_channel")
    security = next(s for s in plan.sections if s.section == "security")
    return dataclasses.replace(
        plan,
        name_change=dataclasses.replace(plan.name_change, desired_short_name="ZZ01"),
        sections=(lora, device, channel, security),
    )


_OK = WriteStatus.CONFIRMED
_UNC = WriteStatus.UNCONFIRMED
_FAIL = WriteStatus.FAILED
_SKIP = WriteStatus.SKIPPED
_NOT_SENT = [("owner", _SKIP), ("lora", _SKIP), ("device", _SKIP)]


@pytest.mark.parametrize(
    ("case", "expected", "security_attempted"),
    [
        (
            "begin_fails",
            [("<verify>", _FAIL), *_NOT_SENT, ("default_channel", _SKIP), ("security", _SKIP)],
            False,
        ),
        (
            "begin_fails_in_place",
            [("<verify>", _FAIL), *_NOT_SENT, ("default_channel", _SKIP), ("security", _SKIP)],
            False,
        ),
        (
            "section_write_fails",
            [("lora", _FAIL), ("device", _SKIP), ("default_channel", _SKIP), ("security", _SKIP)],
            False,
        ),
        (
            "commit_fails",
            [
                ("<verify>", _FAIL),
                ("owner", _UNC),
                ("lora", _UNC),
                ("device", _UNC),
                ("default_channel", _SKIP),
                ("security", _SKIP),
            ],
            False,
        ),
        (
            "commit_fails_in_place",
            [
                ("<verify>", _FAIL),
                ("owner", _UNC),
                ("lora", _UNC),
                ("device", _UNC),
                ("default_channel", _UNC),
                ("security", _UNC),
            ],
            True,
        ),
        (
            # The failed lora write keeps its own FAILED result -- never a
            # second, UNCONFIRMED one -- and device was never sent at all.
            "section_write_and_commit_fail",
            [
                ("lora", _FAIL),
                ("device", _SKIP),
                ("<verify>", _FAIL),
                ("owner", _UNC),
                ("default_channel", _SKIP),
                ("security", _SKIP),
            ],
            False,
        ),
        (
            "mid_plan_reconnect_fails",
            [("<verify>", _FAIL), ("default_channel", _SKIP), ("security", _SKIP)],
            False,
        ),
        (
            "identity_unreadable",
            [("<verify>", _FAIL), ("default_channel", _SKIP), ("security", _SKIP)],
            False,
        ),
        (
            "identity_mismatch",
            [("<verify>", _FAIL), ("default_channel", _SKIP), ("security", _SKIP)],
            False,
        ),
        ("channel_disabled", [("default_channel", _FAIL), ("security", _SKIP)], False),
    ],
)
def test_apply_plan_early_exit_records_every_unsent_section(
    make_live, case: str, expected: list[tuple[str, WriteStatus]], security_attempted: bool
) -> None:
    """Each early exit reports exactly what was and was not sent -- nothing goes missing.

    Section-level results only (``field is None``): the final verify, when
    it runs, adds per-field results for the sections it re-reads.
    Sections already committed before a post-commit stop carry no result of
    their own -- the ``"<verify>"`` failure stands for them.
    """
    plan = _early_exit_plan(make_live)
    kp = generate_keypair()
    first = _FakeIfaceForApply()
    io_error = OSError(errno.EIO, "simulated transaction failure")
    if case.startswith("section_write"):

        def _write_config(section: str) -> None:
            first.localNode.written_sections.append(section)
            if section == "lora":
                raise OSError(errno.EIO, "simulated lora write failure")

        first.localNode.writeConfig = _write_config  # type: ignore[method-assign]
    if case.startswith("begin_fails"):
        first.localNode.begin_error = io_error
    if case.startswith("commit_fails") or case.endswith("commit_fail"):
        first.localNode.commit_error = io_error
    if case == "channel_disabled":
        first.localNode.channels[0].role = channel_pb2.Channel.Role.DISABLED

    refreshed: list[_FakeIfaceForApply] = []
    served = {
        "identity_unreadable": _FakeIfaceUnreadableIdentity(),
        "identity_mismatch": _FakeIfaceForApply(node_num=0xCAFE0002),
    }

    def _on_refresh(_n: int, cur: _FakeIfaceForApply) -> _FakeIfaceForApply:
        fresh = served.get(case) or cur.reopened()
        refreshed.append(fresh)
        return fresh

    session: object
    if case.endswith("in_place"):
        session = InPlaceSession(first)  # type: ignore[arg-type]
    elif case == "mid_plan_reconnect_fails":
        session = _FakeSessionRefreshFailsAfterFirstCall(first)
    else:
        session = _FakeSessionTracksRefresh(first, _on_refresh)

    outcome = apply_plan(plan, session, keypair=kp)  # type: ignore[arg-type]

    assert [(r.section, r.status) for r in outcome.results if r.field is None] == expected, (
        outcome.describe()
    )
    assert outcome.security_attempted is security_attempted
    assert outcome.may_update_database is False
    assert outcome.exit_code == ExitCode.PROVISIONING
    for iface in (first, *refreshed):
        assert ("security" in iface.localNode.written_sections) is security_attempted
    if case.startswith("begin_fails"):
        assert first.localNode.written_sections == []
        assert first.localNode.transaction_calls == ["<begin>"]
        assert refreshed == []
    if first.localNode.commit_error is not None:
        # Never re-read after a failed commit: an open transaction holds its
        # writes in memory only, so a read-back could confirm what a reboot loses.
        assert refreshed == []


def test_apply_plan_in_place_commit_failure_counts_security_as_attempted(
    make_live, make_admin_key
) -> None:
    """In place, security is written inside the transaction, so a failed commit leaves it uncertain.

    ``security_attempted`` used to be hardcoded ``False`` on this arm even
    though ``is_managed``/admin keys had already been sent.
    """
    lockdown = _lockdown_regenerate_plan(make_live, make_admin_key)
    lora = SectionChange(
        section="lora",
        kind=detect.SectionKind.CONFIG,
        changes=(FieldChange(section="lora", field="hop_limit", current=3, desired=5),),
    )
    # A security-only plan opens no transaction at all; lora makes it open one.
    plan = dataclasses.replace(lockdown, sections=(lora, *lockdown.sections))
    iface = _FakeIfaceForApply()
    iface.localNode.commit_error = OSError(errno.EIO, "simulated commit failure")

    outcome = apply_plan(plan, InPlaceSession(iface), keypair=generate_keypair())  # type: ignore[arg-type]

    assert outcome.security_attempted is True
    assert "security" in iface.localNode.written_sections
    security = next(r for r in outcome.results if r.section == "security" and r.field is None)
    assert security.status is WriteStatus.UNCONFIRMED
    assert "commit failed" in security.message
    assert "may or may not have saved it" in security.message
    assert not any(r.status is WriteStatus.CONFIRMED for r in outcome.results)


class _BodyError(Exception):
    """Not a device error, so apply_plan lets it propagate out of the write loop."""


def test_apply_plan_logs_a_commit_failure_that_another_exception_would_hide(
    make_live, caplog: pytest.LogCaptureFixture
) -> None:
    """A commit failing in ``finally`` while another exception propagates is logged, not lost."""
    plan = _early_exit_plan(make_live)
    iface = _FakeIfaceForApply()
    iface.localNode.commit_error = OSError(errno.EIO, "simulated commit failure")

    def _raise(_section: str) -> None:
        raise _BodyError("unexpected")

    iface.localNode.writeConfig = _raise  # type: ignore[method-assign]
    session = _FakeSessionTracksRefresh(iface, _reopen_same_device)

    with (
        caplog.at_level(logging.WARNING, logger="meshprovision.provisioning.apply"),
        pytest.raises(_BodyError),
    ):
        apply_plan(plan, session, keypair=generate_keypair())  # type: ignore[arg-type]

    assert iface.localNode.transaction_calls[-1] == "<commit>"
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING] == [
        "Could not commit the settings transaction: [Errno 5] simulated commit failure"
    ]


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
    persisted = persist_result(
        outcome, nodes=nodes, keys=keys, keypair=kp, origin=KeyOrigin.CAPTURED
    )
    assert persisted is False
    assert db_path.stat().st_mtime_ns == mtime_before
    assert nodes.exists("deadbe01") is False


_NODEDB_ONLY_PUBLIC_KEY: Final = bytes(range(32))


class _FakeIfaceNodeDbReportsAnotherKey(_FakeIfaceForApply):
    """An interface whose own NodeDB entry disagrees with ``localConfig.security``.

    The real ``getPublicKey`` reads the node's NodeDB entry, a store separate
    from ``localConfig``; the base fake derives both from the same bytes, so
    the final verification's NodeDB cross-check could never see them differ.
    """

    def getPublicKey(self) -> str | None:  # noqa: N802 -- real MeshInterface method name
        return base64.b64encode(_NODEDB_ONLY_PUBLIC_KEY).decode("ascii")


def test_verify_flags_a_regenerated_key_the_nodedb_still_reports_differently(make_live) -> None:
    template = _template()
    live = make_live(template, security=make_security(empty=True))
    plan = build_plan(
        PlanInputs(live=live, template=template, db_entry=None, state=detect.NodeState.FACTORY)
    )
    # reopened() keeps type(self), so every reconnect serves the stale NodeDB key.
    session = _FakeSessionTracksRefresh(_FakeIfaceNodeDbReportsAnotherKey(), _reopen_same_device)

    outcome = apply_plan(plan, session, keypair=generate_keypair())  # type: ignore[arg-type]

    key_results = [
        r for r in outcome.results if r.section == "security" and r.field == "public_key"
    ]
    assert len(key_results) == 1
    assert key_results[0].status is WriteStatus.UNCONFIRMED
    assert key_results[0].actual == redact.fingerprint(_NODEDB_ONLY_PUBLIC_KEY)
    assert outcome.may_update_database is False
