"""Tests for the per-section device writers: BLE PIN, apply_field, write_section, channel 0."""

from __future__ import annotations

import errno
from collections.abc import Callable

import pytest
from meshtastic.protobuf import channel_pb2, localonly_pb2

from meshprovision.errors import (
    EnumMappingError,
    PlanConflictError,
    ProvisioningError,
)
from meshprovision.provisioning import detect
from meshprovision.provisioning.apply import (
    apply_field,
    generate_ble_pin,
    write_default_channel,
    write_section,
)
from meshprovision.provisioning.plan import (
    FieldChange,
    SectionChange,
)
from meshprovision.provisioning.plan_admin_keys import KeyPlan
from tests.unit.apply_fakes import (
    FakeIfaceForApply,
    FakeIfaceRaisesOnWrite,
)

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


def test_write_section_unknown_section_raises() -> None:
    iface = FakeIfaceForApply()
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
    iface = FakeIfaceForApply()
    change = SectionChange(section="security", kind=detect.SectionKind.CONFIG, changes=())
    key_plan = KeyPlan(regenerate=True)

    with pytest.raises(PlanConflictError, match="fresh keypair"):
        write_section(iface, change, key_plan=key_plan, keypair=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# write_default_channel.
# ---------------------------------------------------------------------------


def test_write_default_channel_applies_fields_and_calls_write_channel() -> None:
    iface = FakeIfaceForApply()
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
    iface = FakeIfaceForApply()
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
    iface = FakeIfaceForApply()
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
        iface = FakeIfaceForApply()
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
    iface = FakeIfaceForApply()
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
    iface = FakeIfaceRaisesOnWrite(exc)
    change = SectionChange(section="default_channel", kind=detect.SectionKind.CHANNEL, changes=())

    with pytest.raises(ProvisioningError) as exc_info:
        write_default_channel(iface, change)  # type: ignore[arg-type]

    assert exc_info.value.__cause__ is exc


def test_write_default_channel_failed_write_restores_snapshot() -> None:
    """A failed writeChannel must not leave staged values the device never accepted."""
    iface = FakeIfaceRaisesOnWrite(OSError(errno.EIO, "simulated I/O failure"))
    change = SectionChange(
        section="default_channel",
        kind=detect.SectionKind.CHANNEL,
        changes=(
            FieldChange(
                section="default_channel", field="position_precision", current=0, desired=12
            ),
        ),
    )
    pre_call = channel_pb2.ModuleSettings()
    pre_call.CopyFrom(iface.localNode.channels[0].settings.module_settings)

    with pytest.raises(ProvisioningError):
        write_default_channel(iface, change)  # type: ignore[arg-type]

    assert iface.localNode.written_sections == ["default_channel"]
    assert iface.localNode.channels[0].settings.module_settings == pre_call


# ---------------------------------------------------------------------------
# Device I/O exceptions besides OSError/RuntimeError (BLE, MeshInterface, ...)
# must be caught and converted, never escape as a raw traceback.
# ---------------------------------------------------------------------------


def test_write_section_wraps_every_device_io_error(
    device_io_error: Callable[[], BaseException],
) -> None:
    exc = device_io_error()
    iface = FakeIfaceRaisesOnWrite(exc)
    change = SectionChange(section="device", kind=detect.SectionKind.CONFIG, changes=())

    with pytest.raises(ProvisioningError) as exc_info:
        write_section(iface, change)  # type: ignore[arg-type]

    assert exc_info.value.__cause__ is exc


def test_write_section_does_not_swallow_a_programming_error() -> None:
    """Pins the module's "no broad except" discipline against a future regression."""
    iface = FakeIfaceRaisesOnWrite(ZeroDivisionError("boom"))
    change = SectionChange(section="device", kind=detect.SectionKind.CONFIG, changes=())

    with pytest.raises(ZeroDivisionError):
        write_section(iface, change)  # type: ignore[arg-type]
