"""The offline remote diff planner, against the plan's golden cases G1-G8.

Every golden was recomputed from the LoRa time-on-air formula by scripts that import nothing
from ``meshprovision.remote``; float goldens are compared with ``abs=5e-6``.
"""

from __future__ import annotations

import copy
import dataclasses
from pathlib import Path
from typing import Any

import pytest

from meshprovision.config.template import load_template, load_template_text
from meshprovision.remote import plan as plan_module
from meshprovision.remote.budget import (
    MEASURED_TEMPLATE_REPLY_BYTES,
    PRESET_RADIO,
    SLOW_PRESETS,
)
from meshprovision.remote.plan import (
    BUSY_EVIDENCE_MAX_AGE_SECONDS,
    BUSY_SHARE_OF_DUTY,
    FULL_DIFF_PRESETS,
    MEASURED_REPLY_BYTES,
    MODELLED_REGION,
    PATH_CAD_SYMBOLS,
    REQUEST_ORDER,
    SECTION_CHOICES,
    TEMPLATE_DUMP_SECTIONS,
    plan_dry_run,
    template_sections,
)
from meshprovision.remote.plan_types import (
    AirUtilReading,
    Destination,
    DryRunInputs,
    DryRunPlan,
    Gateway,
    GatewayAuthorization,
    NoteCode,
    RefusalCode,
    RequestKind,
    Verdict,
)

pytestmark = pytest.mark.unit

KEY = bytes(range(32))
EXAMPLE = Path(__file__).parents[2] / "src/meshprovision/examples/template.example.yaml"

EXAMPLE_SECTIONS = frozenset(
    {
        "owner",
        "device",
        "position",
        "power",
        "lora",
        "default_channel",
        "security",
        "telemetry",
        "neighbor_info",
        "mqtt",
        "serial",
        "range_test",
        "store_forward",
        "remote_hardware",
        "paxcounter",
    }
)
G7_SECTIONS = frozenset(
    {
        "owner",
        "device",
        "position",
        "power",
        "lora",
        "default_channel",
        "security",
        "mqtt",
        "serial",
        "store_forward",
        "telemetry",
        "neighbor_info",
    }
)


def _inputs(**overrides: Any) -> DryRunInputs:
    """G1 by default: LONG_FAST, ``--section lora``, destination 2.8.3, gateway 2.7.26."""
    fields: dict[str, Any] = {
        "destination": Destination(
            "!deadbe01",
            True,
            template_managed=True,
            firmware="2.8.3",
            authorized_keys=frozenset({KEY}),
        ),
        "gateway": Gateway("!deadbe0a", True, firmware="2.7.26", public_key=KEY),
        "region": "EU_868",
        "preset": "LONG_FAST",
        "hop_limit": 3,
        "override_duty_cycle": False,
        "template_sections": EXAMPLE_SECTIONS,
        "requested_sections": frozenset({"lora"}),
    }
    fields.update(overrides)
    return DryRunInputs(**fields)


def _dest(**overrides: Any) -> Destination:
    fields: dict[str, Any] = {
        "label": "!deadbe01",
        "found": True,
        "template_managed": True,
        "firmware": "2.8.3",
        "authorized_keys": frozenset({KEY}),
        **overrides,
    }
    return Destination(**fields)


def _plan(**overrides: Any) -> DryRunPlan:
    return plan_dry_run(_inputs(**overrides))


def _refusals(plan: DryRunPlan) -> list[str]:
    return [finding.code.value for finding in plan.refusals]


def _notes(plan: DryRunPlan) -> list[str]:
    return [finding.code.value for finding in plan.notes]


def _message(plan: DryRunPlan, code: RefusalCode | NoteCode) -> str:
    return next(f.message for f in (*plan.refusals, *plan.notes) if f.code == code)


def _cli_dumps(template: Any) -> dict[str, dict[str, object]]:
    return {
        name: getattr(template, name).model_dump(exclude_none=True)
        for name in TEMPLATE_DUMP_SECTIONS
    }


# ---- template sections


def test_template_sections_of_the_example_template() -> None:
    template = load_template(EXAMPLE)

    got = template_sections(
        _cli_dumps(template), template.option_state(), has_admin_nodes=bool(template.admin_nodes)
    )

    assert got == EXAMPLE_SECTIONS


def test_template_sections_of_a_minimal_template() -> None:
    template = load_template_text("version: 1\n")

    got = template_sections(
        _cli_dumps(template), template.option_state(), has_admin_nodes=bool(template.admin_nodes)
    )

    assert got == {"owner", "device", "lora", "security"}


@pytest.mark.parametrize(
    ("dumps", "options", "admin", "expected"),
    [
        pytest.param({}, {}, False, {"owner"}, id="empty"),
        pytest.param({}, {}, True, {"owner", "security"}, id="admin-nodes-add-security"),
        pytest.param({}, {"audio": True}, False, {"owner"}, id="option-without-enabled"),
        pytest.param({}, {"bogus": True}, False, {"owner"}, id="option-not-a-module"),
        pytest.param({"telemetry": {}}, {}, False, {"owner"}, id="empty-dump"),
        pytest.param(
            {"lora": {"hop_limit": 3}}, {"mqtt": False}, False, {"owner", "lora", "mqtt"}, id="set"
        ),
    ],
)
def test_template_sections_rules(
    dumps: dict[str, dict[str, object]],
    options: dict[str, bool],
    admin: bool,
    expected: set[str],
) -> None:
    assert template_sections(dumps, options, has_admin_nodes=admin) == expected


def test_template_sections_rejects_an_unknown_dump() -> None:
    with pytest.raises(ValueError, match="bluetooth"):
        template_sections({"bluetooth": {"enabled": True}}, {}, has_admin_nodes=False)


# ---- constants


def test_measured_reply_bytes() -> None:
    assert len(MEASURED_REPLY_BYTES) == 13
    assert tuple(MEASURED_REPLY_BYTES.values()) == MEASURED_TEMPLATE_REPLY_BYTES
    assert MEASURED_REPLY_BYTES["default_channel"] == 77
    assert MEASURED_REPLY_BYTES["security"] == 174


def test_full_diff_presets_are_the_250_khz_ones() -> None:
    assert set(PRESET_RADIO) - SLOW_PRESETS == FULL_DIFF_PRESETS
    assert len(FULL_DIFF_PRESETS) == 5


def test_policy_values_are_the_documented_ones() -> None:
    assert (
        MODELLED_REGION,
        PATH_CAD_SYMBOLS,
        BUSY_SHARE_OF_DUTY,
        BUSY_EVIDENCE_MAX_AGE_SECONDS,
    ) == ("EU_868", 4, 0.5, 86400)


def test_request_order_and_section_choices() -> None:
    assert REQUEST_ORDER[0] == "metadata"
    assert "metadata" not in SECTION_CHOICES
    assert REQUEST_ORDER[1:] == SECTION_CHOICES
    modules = REQUEST_ORDER[8:]
    assert modules[0] == "mqtt"
    assert modules[-1] == "traffic_management"
    assert len(modules) == 14


# ---- golden plans


def test_g1_is_allowed() -> None:
    plan = _plan()

    assert plan.verdict is Verdict.ALLOWED
    assert plan.refusals == ()
    assert _notes(plan) == ["path_unknown", "busy_unknown", "never_written"]
    assert plan.security_read is False
    assert plan.gateway_authorization is GatewayAuthorization.AUTHORIZED
    assert plan.gateway_attempts == 3
    assert [(r.section, r.kind, r.reply_bytes, r.measured) for r in plan.requests] == [
        ("metadata", RequestKind.METADATA, 91, True),
        ("lora", RequestKind.CONFIG, 89, True),
    ]
    estimate = plan.estimate
    assert estimate is not None
    assert estimate.slot_ms == 44
    assert estimate.settle.max_seconds == 120.0
    assert [t.links for t in estimate.timings] == [1, 2, 3, 4]
    expected = [
        (7.4136, 7.4136, 134.83, 134.83),
        (22.8831, 34.1471, 165.77, 188.29),
        (38.3527, 60.8807, 196.71, 241.76),
        (53.8223, 87.6143, 227.64, 295.23),
    ]
    for timing, (typical, worst, run_typical, run_worst) in zip(
        estimate.timings, expected, strict=True
    ):
        assert timing.deadline_typical == pytest.approx(typical, abs=5e-5)
        assert timing.deadline_worst_case == pytest.approx(worst, abs=5e-5)
        assert timing.longest_run_typical == pytest.approx(run_typical, abs=5e-3)
        assert timing.longest_run_worst_case == pytest.approx(run_worst, abs=5e-3)
    typical_ledger, worst_ledger = estimate.ledger, estimate.ledger_worst_case
    assert (typical_ledger.cw, worst_ledger.cw) == (7, 8)
    assert typical_ledger.gateway_seconds == pytest.approx(1.282048, abs=5e-6)
    assert typical_ledger.relay_seconds == pytest.approx(3.137536, abs=5e-6)
    assert typical_ledger.destination_seconds == pytest.approx(1.855488, abs=5e-6)
    assert typical_ledger.per_window == 11
    assert worst_ledger.relay_seconds == pytest.approx(4.614384, abs=5e-6)
    assert worst_ledger.per_window == 7


def test_g2_example_on_long_fast_is_allowed_with_two_notes() -> None:
    plan = _plan(
        destination=_dest(firmware="2.7.11"),
        gateway=None,
        requested_sections=frozenset(),
    )

    assert plan.verdict is Verdict.ALLOWED
    assert _notes(plan) == [
        "path_unknown",
        "gateway_assumed",
        "security_skipped",
        "admin_key_fallback",
        "busy_unknown",
        "largest_replies_over_share",
        "worst_case_over_share",
        "never_written",
    ]
    worst = _message(plan, NoteCode.WORST_CASE_OVER_SHARE)
    assert "45.57 s" in worst
    assert "strong links, SNR 10 to 15 dB" in worst
    assert "this does not refuse the read" in worst
    assert "41.96 s" in _message(plan, NoteCode.LARGEST_REPLIES_OVER_SHARE)
    assert len(plan.requests) == 15
    assert plan.firmware_version == (2, 7, 11)
    assert plan.security_read is False
    assert plan.gateway_attempts == 5
    assert plan.estimate is not None
    assert plan.estimate.ledger.relay_seconds == pytest.approx(30.98624, abs=5e-6)
    assert plan.estimate.ledger.per_window == 1


def test_g3_full_diff_on_long_moderate_is_refused_twice() -> None:
    plan = _plan(preset="LONG_MODERATE", gateway=None, requested_sections=frozenset())

    assert plan.verdict is Verdict.REFUSED
    assert _refusals(plan) == ["full_diff_on_slow_preset", "over_polite_share"]
    over = _message(plan, RefusalCode.OVER_POLITE_SHARE)
    assert "152.05 s" in over
    assert "contention window 7" in over
    slow = _message(plan, RefusalCode.FULL_DIFF_ON_SLOW_PRESET)
    assert "refused by policy" in slow
    assert "costs one relay more" not in slow
    assert _notes(plan) == [
        "path_unknown",
        "gateway_assumed",
        "two_frequency_slots",
        "busy_unknown",
        "never_written",
    ]
    assert plan.security_read is True
    assert len(plan.requests) == 16


@pytest.mark.parametrize(
    ("overrides", "relay", "notes"),
    [
        pytest.param(
            {"preset": "LONG_SLOW", "requested_sections": frozenset({"device"})},
            28.220544,
            [
                "path_unknown",
                "gateway_assumed",
                "two_frequency_slots",
                "busy_unknown",
                "largest_replies_over_share",
                "never_written",
            ],
            id="G4",
        ),
        pytest.param(
            {"preset": "LONG_MODERATE"},
            13.733568,
            [
                "path_unknown",
                "gateway_assumed",
                "two_frequency_slots",
                "busy_unknown",
                "never_written",
            ],
            id="G6",
        ),
        pytest.param(
            {"preset": "MEDIUM_SLOW", "requested_sections": frozenset()},
            17.915904,
            ["path_unknown", "gateway_assumed", "busy_unknown", "never_written"],
            id="G8",
        ),
    ],
)
def test_g4_g6_g8_fit(overrides: dict[str, Any], relay: float, notes: list[str]) -> None:
    plan = _plan(gateway=None, **overrides)

    assert plan.verdict is Verdict.ALLOWED
    assert _notes(plan) == notes
    assert plan.estimate is not None
    assert plan.estimate.ledger.relay_seconds == pytest.approx(relay, abs=5e-6)


def test_g4_largest_replies_message() -> None:
    plan = _plan(gateway=None, preset="LONG_SLOW", requested_sections=frozenset({"device"}))

    assert "55.59 s" in _message(plan, NoteCode.LARGEST_REPLIES_OVER_SHARE)


def test_g5_medium_fast_with_an_authorized_gateway() -> None:
    plan = _plan(
        gateway=Gateway("!deadbe0a", True, firmware="2.8.3", public_key=KEY),
        preset="MEDIUM_FAST",
        requested_sections=frozenset(),
    )

    assert plan.verdict is Verdict.ALLOWED
    assert _notes(plan) == ["path_unknown", "busy_unknown", "never_written"]
    assert plan.gateway_attempts == 5
    assert plan.estimate is not None
    assert plan.estimate.ledger.relay_seconds == pytest.approx(9.838592, abs=5e-6)
    assert plan.estimate.ledger.per_window == 3


def test_g7_shows_both_notes() -> None:
    plan = _plan(gateway=None, template_sections=G7_SECTIONS, requested_sections=frozenset())

    assert plan.verdict is Verdict.ALLOWED
    assert len(plan.requests) == 13
    assert _notes(plan) == [
        "path_unknown",
        "gateway_assumed",
        "busy_unknown",
        "largest_replies_over_share",
        "worst_case_over_share",
        "never_written",
    ]
    assert "36.37 s" in _message(plan, NoteCode.LARGEST_REPLIES_OVER_SHARE)
    assert "36.44 s" in _message(plan, NoteCode.WORST_CASE_OVER_SHARE)


# ---- refusals and notes


@pytest.mark.parametrize(
    ("destination", "code", "fragments"),
    [
        pytest.param(
            Destination("!deadbe01", False),
            "not_in_database",
            ["!deadbe01 is not in the database"],
            id="not-found",
        ),
        pytest.param(_dest(archived=True), "archived", ["archived"], id="archived"),
        pytest.param(
            _dest(template_managed=False),
            "not_template_managed",
            ["`mesh provision --enroll`"],
            id="observed",
        ),
        pytest.param(_dest(firmware=""), "firmware_unknown", ["none recorded"], id="no-firmware"),
        pytest.param(
            _dest(firmware="garbage"), "firmware_unknown", ["(garbage)"], id="garbage-firmware"
        ),
        pytest.param(
            _dest(firmware="2.6.13"), "firmware_too_old", ["2.6.13", "2.7.0"], id="too-old"
        ),
    ],
)
def test_destination_row_refusals(
    destination: Destination, code: str, fragments: list[str]
) -> None:
    plan = _plan(destination=destination, gateway=None)

    assert plan.verdict is Verdict.REFUSED
    assert code in _refusals(plan)
    message = next(f.message for f in plan.refusals if f.code == code)
    assert all(fragment in message for fragment in fragments)
    if code == "not_in_database":
        assert _refusals(plan) == ["not_in_database"]
        assert "admin_key_fallback" not in _notes(plan)
        assert "busy_unknown" not in _notes(plan)


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        pytest.param({"region": "EU_433"}, "region_not_modelled", id="region"),
        pytest.param({"preset": None}, "preset_not_modelled", id="no-preset"),
        pytest.param({"preset": "SHORT_TURBO"}, "preset_not_modelled", id="unknown-preset"),
    ],
)
def test_region_and_preset_refusals_drop_the_estimate(overrides: dict[str, Any], code: str) -> None:
    plan = _plan(**overrides)

    assert plan.estimate is None
    assert code in _refusals(plan)
    assert [r.section for r in plan.requests] == ["metadata", "lora"]
    # what depends only on the requests stays; the path and the cost need the model
    assert "never_written" in _notes(plan)
    assert "path_unknown" not in _notes(plan)


def test_override_duty_cycle_is_refused() -> None:
    plan = _plan(override_duty_cycle=True)

    assert _refusals(plan) == ["override_duty_cycle"]
    assert "ETSI EN 300 220" in _message(plan, RefusalCode.OVERRIDE_DUTY_CYCLE)


def test_unknown_requested_section() -> None:
    plan = _plan(
        template_sections=frozenset({"owner", "lora"}),
        requested_sections=frozenset({"paxcounter", "audio"}),
    )

    assert _message(plan, RefusalCode.SECTION_NOT_IN_TEMPLATE) == (
        "the template sets nothing in audio, paxcounter, so there is nothing to compare."
    )
    assert [r.section for r in plan.requests] == ["metadata"]


def test_security_section_below_2_8_is_refused() -> None:
    plan = _plan(destination=_dest(firmware="2.7.26"), requested_sections=frozenset({"security"}))

    assert _refusals(plan) == ["security_below_2_8"]
    assert plan.security_read is False
    assert [r.section for r in plan.requests] == ["metadata"]


@pytest.mark.parametrize(
    ("firmware", "requested", "code", "message"),
    [
        pytest.param(
            "2.7.26",
            frozenset(),
            NoteCode.SECURITY_SKIPPED,
            "security is not read: below firmware 2.8.0 the reply carries !deadbe01's "
            "private key over the mesh.",
            id="2.7-full",
        ),
        pytest.param(
            "2.7.26",
            frozenset({"security"}),
            RefusalCode.SECURITY_BELOW_2_8,
            "security is read only from firmware 2.8.0 on; below it the reply carries "
            "!deadbe01's private key over the mesh.",
            id="2.7-section",
        ),
        pytest.param(
            "",
            frozenset(),
            NoteCode.SECURITY_SKIPPED,
            "security is not read: !deadbe01's firmware version is unknown, and below 2.8.0 "
            "the reply carries !deadbe01's private key over the mesh.",
            id="unknown-full",
        ),
        pytest.param(
            "2.x",
            frozenset({"security"}),
            RefusalCode.SECURITY_BELOW_2_8,
            "security is read only from firmware 2.8.0 on; !deadbe01's firmware version is "
            "unknown, and below 2.8.0 the reply carries !deadbe01's private key over the mesh.",
            id="unparseable-section",
        ),
    ],
)
def test_security_findings_name_the_version_only_when_it_is_known(
    firmware: str, requested: frozenset[str], code: RefusalCode | NoteCode, message: str
) -> None:
    plan = _plan(destination=_dest(firmware=firmware), requested_sections=requested)

    assert _message(plan, code) == message
    assert plan.security_read is False


@pytest.mark.parametrize("requested", [frozenset(), frozenset({"security"})])
def test_a_node_not_in_the_database_gets_no_security_finding(requested: frozenset[str]) -> None:
    plan = _plan(destination=Destination("!deadbe01", False), requested_sections=requested)

    assert _refusals(plan) == ["not_in_database"]
    assert "security_skipped" not in _notes(plan)
    assert plan.security_read is False


def _gateway_case(**overrides: Any) -> dict[str, Any]:
    return {"gateway": Gateway("!deadbe0a", True, firmware="2.8.3", public_key=KEY), **overrides}


@pytest.mark.parametrize(
    ("overrides", "authorization", "attempts", "refusals", "fragment"),
    [
        pytest.param(
            {"gateway": None},
            GatewayAuthorization.NOT_CHECKED,
            5,
            [],
            "no --gateway",
            id="none",
        ),
        pytest.param(
            {"gateway": Gateway("!deadbe01", True, firmware="2.8.3", public_key=KEY)},
            GatewayAuthorization.NO_RECORD,
            5,
            ["gateway_is_destination"],
            "itself",
            id="is-destination",
        ),
        pytest.param(
            {"gateway": Gateway("!deadbe0a", False)},
            GatewayAuthorization.NO_RECORD,
            5,
            ["gateway_not_in_database"],
            "not an active database node",
            id="not-found",
        ),
        pytest.param(
            {
                "gateway": Gateway(
                    "!deadbe0a", True, archived=True, firmware="2.8.3", public_key=KEY
                )
            },
            GatewayAuthorization.NO_RECORD,
            5,
            ["gateway_not_in_database"],
            "not an active database node",
            id="archived",
        ),
        pytest.param(
            {"gateway": Gateway("!deadbe0a", True, firmware="2.8.3")},
            GatewayAuthorization.KEY_UNKNOWN,
            5,
            ["gateway_key_unknown"],
            "`mesh adopt`",
            id="no-key",
        ),
        pytest.param(
            {"gateway": Gateway("!deadbe0a", True, firmware="2.8.3", public_key=bytes(32))},
            GatewayAuthorization.NOT_AUTHORIZED,
            5,
            ["gateway_not_authorized"],
            "do not include",
            id="foreign-key",
        ),
        pytest.param(
            {"gateway": Gateway("!deadbe0a", True, firmware="", public_key=KEY)},
            GatewayAuthorization.AUTHORIZED,
            5,
            [],
            "recorded firmware version does not parse",
            id="firmware-unparseable",
        ),
        pytest.param(
            {"gateway": Gateway("!deadbe0a", True, firmware="2.8.0", public_key=KEY)},
            GatewayAuthorization.AUTHORIZED,
            5,
            [],
            None,
            id="firmware-2.8.0",
        ),
        pytest.param(
            {"destination": Destination("!deadbe01", False)},
            GatewayAuthorization.NO_RECORD,
            5,
            ["not_in_database"],
            None,
            id="destination-not-found",
        ),
    ],
)
def test_gateway_rules(
    overrides: dict[str, Any],
    authorization: GatewayAuthorization,
    attempts: int,
    refusals: list[str],
    fragment: str | None,
) -> None:
    plan = _plan(**_gateway_case(**overrides))

    assert plan.gateway_authorization is authorization
    assert plan.gateway_attempts == attempts
    assert _refusals(plan) == refusals
    if fragment is not None:
        assert any(fragment in f.message for f in (*plan.refusals, *plan.notes))


@pytest.mark.parametrize(
    ("percent", "age", "code"),
    [
        pytest.param(5.0, 0, None, id="at-the-threshold-passes"),
        pytest.param(5.01, 0, "destination_busy", id="just-above"),
        pytest.param(9.0, 86400, "destination_busy", id="oldest-evidence-counts"),
        pytest.param(9.0, 86401, "busy_unknown", id="too-old"),
        pytest.param(None, 0, "busy_unknown", id="no-reading"),
    ],
)
def test_busy_rules(percent: float | None, age: float, code: str | None) -> None:
    reading = None if percent is None else AirUtilReading(percent, age)
    plan = _plan(destination=_dest(air_util_tx=reading))

    if code == "destination_busy":
        message = _message(plan, RefusalCode.DESTINATION_BUSY)
        assert _refusals(plan) == ["destination_busy"]
        assert "5.01 %" in message or "9.00 %" in message
        assert "above 5 % (half of EU_868's 10 % limit)" in message
        assert "drops its own replies" in message
    else:
        assert _refusals(plan) == []
        assert ("busy_unknown" in _notes(plan)) is (code == "busy_unknown")
    if code == "busy_unknown" and percent is None:
        assert "`mesh health`" in _message(plan, NoteCode.BUSY_UNKNOWN)
    if code is None:
        assert "busy_unknown" not in _notes(plan)


@pytest.mark.parametrize(
    ("hop_limit", "timings", "allows", "stops"),
    [
        (0, 1, "allows 1", False),
        (3, 4, "allows 4", False),
        (6, 7, "allows 7", False),
        (7, 7, "allows 8", True),
    ],
)
def test_hop_limit_ranges(hop_limit: int, timings: int, allows: str, stops: bool) -> None:
    plan = _plan(hop_limit=hop_limit)

    assert plan.estimate is not None
    assert len(plan.estimate.timings) == timings
    message = _message(plan, NoteCode.PATH_UNKNOWN)
    assert allows in message
    assert ("the model stops at 7" in message) is stops
    assert "how many pay is unknown" in message


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"hop_limit": -1}, id="hop-limit-low"),
        pytest.param({"hop_limit": 8}, id="hop-limit-high"),
        pytest.param({"template_sections": frozenset({"metadata"})}, id="metadata-section"),
        pytest.param({"requested_sections": frozenset({"bogus"})}, id="bogus-request"),
        pytest.param(
            {"destination": _dest(air_util_tx=AirUtilReading(1.0, -1.0))}, id="negative-age"
        ),
    ],
)
def test_bad_inputs_raise(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _plan(**overrides)


def test_findings_are_sorted_by_code_order() -> None:
    plan = _plan(
        destination=_dest(
            archived=True,
            template_managed=False,
            firmware="2.6.13",
            authorized_keys=frozenset({KEY}),
            air_util_tx=AirUtilReading(9.0, 60),
        ),
        gateway=Gateway("!deadbe0a", True, firmware="2.8.3", public_key=bytes(32)),
        override_duty_cycle=True,
        preset="LONG_SLOW",
        requested_sections=frozenset(),
    )

    codes = [f.code for f in plan.refusals]

    assert codes == sorted(codes, key=list(RefusalCode).index)
    assert {
        "archived",
        "not_template_managed",
        "firmware_too_old",
        "override_duty_cycle",
        "full_diff_on_slow_preset",
        "gateway_not_authorized",
        "destination_busy",
    } <= {c.value for c in codes}
    notes = [f.code for f in plan.notes]
    assert notes == sorted(notes, key=list(NoteCode).index)


def test_never_written_lists_what_is_read() -> None:
    g1 = _plan()
    full = _plan(gateway=None, requested_sections=frozenset())

    assert "never writes lora, lora.override_duty_cycle." in _message(g1, NoteCode.NEVER_WRITTEN)
    assert (
        "never writes lora, lora.override_duty_cycle, default_channel, security, device.role"
        in (_message(full, NoteCode.NEVER_WRITTEN))
    )
    assert _message(full, NoteCode.NEVER_WRITTEN).endswith(
        "device.node_info_broadcast_secs, power, mqtt, owner.is_licensed."
    )
    assert "`mesh provision`" in _message(full, NoteCode.NEVER_WRITTEN)


def test_the_inputs_are_not_mutated() -> None:
    inputs = _inputs(requested_sections=frozenset())
    before = copy.deepcopy(inputs)

    plan_dry_run(inputs)

    assert inputs == before
    assert dataclasses.is_dataclass(inputs)


def test_a_region_without_a_duty_limit_judges_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the model ever covers a region without a duty limit, no share applies."""
    monkeypatch.setattr(plan_module, "MODELLED_REGION", "US")

    plan = _plan(region="US", requested_sections=frozenset())

    assert plan.estimate is not None
    assert plan.estimate.ledger.fits is None
    assert plan.refusals == ()
    assert "largest_replies_over_share" not in _notes(plan)
    assert "worst_case_over_share" not in _notes(plan)


def test_the_module_holds_no_build_plan_or_io() -> None:
    assert not hasattr(plan_module, "build_plan")
