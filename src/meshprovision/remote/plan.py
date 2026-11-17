"""An offline plan for a read-only remote diff of one node.

It says which requests the diff would send, what a run could cost, and which rules refuse it.

The inputs are plain facts the caller gathers from the template, the database and the local
health history. So this module never sees a device, a file, the clock or ``build_plan``.

The plan is a preflight estimate. Its timing and airtime come from
:mod:`~meshprovision.remote.budget` and :mod:`~meshprovision.remote.ledger`, a worst-case
model calibrated in simulator runs, never on hardware. Airtime is judged at the typical
contention window and shown at the worst case too.

The path is unknown offline. On a first contact every rebroadcasting node that hears a request
with hops left sends it again, not only the nodes on the eventual path [source:
``FloodingRouter.cpp:75``, ``NextHopRouter.cpp:34``]; once a 2.8 node has learnt a next hop,
only that relay does. So deadlines and run times are given for every link count the hop limit
allows, and the charge is per relay: what one relay pays does not depend on the path, and how
many pay is unknown.

Every constant ends with its class in brackets.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType
from typing import Final

from meshprovision.enums import MODULE_SECTIONS, MODULES_WITHOUT_ENABLED
from meshprovision.lora_regions import REGION_BANDS
from meshprovision.remote.budget import (
    HOUR_SECONDS,
    MAX_LINKS,
    MAX_REPLY_BYTES,
    MEASURED_TEMPLATE_REPLY_BYTES,
    POLITE_RELAY_SHARE,
    PRESET_RADIO,
    SLOW_PRESETS,
    TYPICAL_CW,
    WORST_CASE_CW,
    SettleRule,
    deadline_seconds,
    settle_rule,
    slot_ms,
)
from meshprovision.remote.firmware import (
    GATEWAY_ATTEMPTS_FROM_2_8,
    PRIVATE_KEY_REDACTED_MIN_FIRMWARE,
    REMOTE_READ_MIN_FIRMWARE,
    FirmwareTraits,
    firmware_traits,
)
from meshprovision.remote.ledger import Ledger, diff_ledger
from meshprovision.remote.plan_types import (
    Destination,
    DryRunInputs,
    DryRunPlan,
    Estimate,
    Finding,
    Gateway,
    GatewayAuthorization,
    LinkTiming,
    NoteCode,
    RefusalCode,
    ReplySize,
    Request,
    RequestKind,
)
from meshprovision.remote.refused import REFUSED_CONFIG

__all__ = [
    "BUSY_EVIDENCE_MAX_AGE_SECONDS",
    "BUSY_SHARE_OF_DUTY",
    "FULL_DIFF_PRESETS",
    "MEASURED_REPLY_BYTES",
    "MODELLED_REGION",
    "PATH_CAD_SYMBOLS",
    "REQUEST_ORDER",
    "SECTION_CHOICES",
    "SECURITY_REPLY_BYTES",
    "TEMPLATE_DUMP_SECTIONS",
    "plan_dry_run",
    "template_sections",
]

MODELLED_REGION: Final[str] = "EU_868"
"""The one region the plan models. [policy: PRESETS-PL-RESULTS covers EU_868 only (its
presets, slots, duty cycle and the simulator runs); the project serves the Polish mesh]"""

FULL_DIFF_PRESETS: Final[frozenset[str]] = frozenset(
    name for name, radio in PRESET_RADIO.items() if radio.bandwidth_hz == 250_000
)
"""The presets a full diff (no --section) is planned on at all: the five 250 kHz ones. The
``full_diff_on_slow_preset`` rule refuses the other two,
:data:`~meshprovision.remote.budget.SLOW_PRESETS`, and names them in its message;
``test_full_diff_presets_are_the_250_khz_ones`` pins that the two sets split
:data:`~meshprovision.remote.budget.PRESET_RADIO`. [policy: OPINION Q2 item 3; PRESETS-PL
sections 1.2 and 2.3: one full diff costs an LM or LS relay several times the polite share]"""

PATH_CAD_SYMBOLS: Final[int] = 4
"""The CAD symbols assumed for the relays' slot. [policy: the relays and their firmware are
unknown offline; 4 (2.8 on an SX126x-family radio, RadioInterface.h:107, SX126xInterface.h:97)
gives the longer slot, so the longer deadline and the larger spurious factor]"""

BUSY_SHARE_OF_DUTY: Final[float] = 0.5
"""A destination whose last-known transmit air utilisation is above this share of the region's
duty cycle (5 % on EU_868) is refused. [policy: PRESETS-PL section 2.3 wrote this rule for
relays, whose figures are unknown offline; it is applied to the destination, the one node
whose last-known ``air_util_tx`` the local health history holds. The firmware's own polite
gate is at the same half, airtime.h:41 isTxAllowedAirUtil "at HALF the duty cycle"]"""

BUSY_EVIDENCE_MAX_AGE_SECONDS: Final[int] = 24 * 3600
"""An air-utilisation reading older than this says nothing about the node's load now.
[policy]"""

TEMPLATE_DUMP_SECTIONS: Final[tuple[str, ...]] = (
    "device",
    "position",
    "power",
    "lora",
    "default_channel",
    "security",
    "telemetry",
    "neighbor_info",
)
"""The template sections whose set fields (defaults included) make a section worth reading.
[source: config/template.py TemplateConfig]"""

REQUEST_ORDER: Final[tuple[str, ...]] = (
    "metadata",
    "owner",
    "device",
    "position",
    "power",
    "lora",
    "default_channel",
    "security",
    *MODULE_SECTIONS,
)
"""The order requests are planned in: the metadata first (it carries the firmware version),
then provision's SECTION_ORDER, then the modules in enums order. [policy]"""

SECTION_CHOICES: Final[tuple[str, ...]] = REQUEST_ORDER[1:]
"""What --section accepts: every request but the metadata, which is always sent. [policy]"""

_MEASURED_SECTIONS: Final[tuple[str, ...]] = (
    "metadata",
    "owner",
    "device",
    "position",
    "power",
    "network",
    "display",
    "lora",
    "bluetooth",
    "security",
    "mqtt",
    "telemetry",
    "default_channel",
)

MEASURED_REPLY_BYTES: Final[Mapping[str, int]] = MappingProxyType(
    dict(zip(_MEASURED_SECTIONS, MEASURED_TEMPLATE_REPLY_BYTES, strict=True))
)
"""On-air reply size per section where one was measured; any other section is planned at
MAX_REPLY_BYTES, and ``security`` at :data:`SECURITY_REPLY_BYTES`. ``network``, ``display``
and ``bluetooth`` were measured but are never planned (:data:`REQUEST_ORDER` leaves them out:
the template sets none of them). [measured: A1 run s01_3, simulator, firmware 2.7.26; T1
section d lists the 13 sections in this order, "channel0" being default_channel]"""

_PRIVATE_KEY_FIELD_BYTES: Final[int] = 34
"""``SecurityConfig.private_key`` in a reply: a 1 B tag, a 1 B length and the 32 B key.
[source: ``config.pb.h`` ``SecurityConfig`` field 2, ``PB_BYTES_ARRAY_T(32)``]"""

_SIGNATURE_POLICY_FIELD_BYTES: Final[int] = 2
"""``SecurityConfig.packet_signature_policy`` in a reply set away from its default: a 1 B tag
and a 1 B enum value. 2.7.26 has no such field. [source: 2.8.3 ``config.pb.h``
``SecurityConfig`` field 9]"""

SECURITY_REPLY_BYTES: Final[int] = (
    MEASURED_REPLY_BYTES["security"] - _PRIVATE_KEY_FIELD_BYTES + _SIGNATURE_POLICY_FIELD_BYTES
)
"""The ``security`` reply's on-air size as planned (142): the plan reads it only from firmware
2.8.0 on, which leaves the private key out of a remote reply (``AdminModule.cpp:1528-1531``
sets its size to 0, so the field is not encoded), and 2.8 may add the signature policy.
[model: the 2.7.26 measurement less the key field plus the policy field; an upper bound for
the measured configuration, as a shorter enclosing length prefix only makes it smaller]"""

_CONFIG_REQUESTS: Final[frozenset[str]] = frozenset(
    {"device", "position", "power", "lora", "security"}
)

_MAX_HOP_LIMIT: Final[int] = MAX_LINKS
"""The largest hop limit a template sets, the firmware's ``HOP_MAX``, as
:data:`~meshprovision.remote.budget.MAX_LINKS` is."""


_CODE_ORDER: Final[Mapping[RefusalCode | NoteCode, int]] = MappingProxyType(
    {code: index for index, code in enumerate((*RefusalCode, *NoteCode))}
)
"""Declaration order, which is report order (a code is in one enum only)."""


def _dotted(version: tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def template_sections(
    dumps: Mapping[str, Mapping[str, object]],
    option_state: Mapping[str, bool],
    *,
    has_admin_nodes: bool,
) -> frozenset[str]:
    """Return the sections the template sets, which a full diff would read.

    The union of ``owner`` (always), each section whose dump is non-empty, ``security`` when
    the template lists admin nodes, and each module the template switches on or off. The
    dumps carry the template's own defaults (``model_dump(exclude_none=True)``), so
    ``device`` (role CLIENT), ``lora`` (region, preset, hop limit) and ``security``
    (``is_managed`` and ``admin_channel_enabled`` false) are in every template's sections.
    They are also in every ``mesh provision`` plan, which diffs the same dumps.

    Args:
        dumps: Section name to its set fields, for the names in
            :data:`TEMPLATE_DUMP_SECTIONS`.
        option_state: Module name to whether the template enables it.
        has_admin_nodes: The template lists admin nodes.

    Returns:
        The section names.

    Raises:
        ValueError: If a dump is named outside :data:`TEMPLATE_DUMP_SECTIONS`.
    """
    unknown = sorted(set(dumps) - set(TEMPLATE_DUMP_SECTIONS))
    if unknown:
        raise ValueError(f"unknown template dump sections: {', '.join(unknown)}")
    return frozenset(
        {
            "owner",
            *(name for name, fields in dumps.items() if fields),
            *(("security",) if has_admin_nodes else ()),
            *(
                name
                for name in option_state
                if name in MODULE_SECTIONS and name not in MODULES_WITHOUT_ENABLED
            ),
        }
    )


def _destination_findings(dest: Destination, traits: FirmwareTraits) -> tuple[Finding, ...]:
    node = dest.label
    floor = _dotted(REMOTE_READ_MIN_FIRMWARE)
    if not dest.found:
        return (
            Finding(
                RefusalCode.NOT_IN_DATABASE,
                f"{node} is not in the database; remote work only reads nodes the database "
                "manages.",
            ),
        )
    findings: list[Finding] = []
    if dest.archived:
        findings.append(Finding(RefusalCode.ARCHIVED, f"{node} is archived in the database."))
    if not dest.template_managed:
        findings.append(
            Finding(
                RefusalCode.NOT_TEMPLATE_MANAGED,
                f"{node} is not template-managed; remote work only reads nodes enrolled with "
                "`mesh provision --enroll`.",
            )
        )
    if traits.version is None:
        shown = dest.firmware or "none recorded"
        findings.append(
            Finding(
                RefusalCode.FIRMWARE_UNKNOWN,
                f"the database records no usable firmware version for {node} ({shown}); a "
                f"remote read needs {floor} or later.",
            )
        )
    elif not traits.remote_read_allowed:
        findings.append(
            Finding(
                RefusalCode.FIRMWARE_TOO_OLD,
                f"{node} runs firmware {_dotted(traits.version)} (last recorded); a remote "
                f"read needs {floor} or later.",
            )
        )
    elif not traits.admin_key_fallback:
        redacted = _dotted(PRIVATE_KEY_REDACTED_MIN_FIRMWARE)
        findings.append(
            Finding(
                NoteCode.ADMIN_KEY_FALLBACK,
                f"{node} runs firmware below {redacted}, which decrypts the gateway's "
                "requests only once it has heard the gateway's node info.",
            )
        )
    return tuple(findings)


def _model_findings(inputs: DryRunInputs) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    if inputs.region != MODELLED_REGION:
        findings.append(
            Finding(
                RefusalCode.REGION_NOT_MODELLED,
                f"the template's region is {inputs.region}; the timing model and these rules "
                f"cover {MODELLED_REGION} only.",
            )
        )
    if inputs.preset is None:
        findings.append(
            Finding(
                RefusalCode.PRESET_NOT_MODELLED,
                "the template runs no modem preset (use_preset must be true and modem_preset "
                "set); the timing model covers the seven EU_868 presets only.",
            )
        )
    elif inputs.preset not in PRESET_RADIO:
        findings.append(
            Finding(
                RefusalCode.PRESET_NOT_MODELLED,
                f"the timing model has no figures for {inputs.preset}; it covers the seven "
                "EU_868 presets only.",
            )
        )
    if inputs.override_duty_cycle:
        reason = REFUSED_CONFIG["lora.override_duty_cycle"]
        findings.append(
            Finding(
                RefusalCode.OVERRIDE_DUTY_CYCLE,
                f"the template sets lora.override_duty_cycle: true, which {reason}.",
            )
        )
    if inputs.preset in SLOW_PRESETS:
        findings.append(
            Finding(
                NoteCode.TWO_FREQUENCY_SLOTS,
                f"{inputs.preset} has two frequency slots on {MODELLED_REGION}, picked by the "
                f"primary channel's name; the gateway reaches {inputs.destination.label} only "
                "on its own slot.",
            )
        )
    return tuple(findings)


def _sections(
    inputs: DryRunInputs, traits: FirmwareTraits
) -> tuple[frozenset[str], tuple[Finding, ...]]:
    findings: list[Finding] = []
    node = inputs.destination.label
    full = not inputs.requested_sections
    missing = inputs.requested_sections - inputs.template_sections
    if missing:
        names = ", ".join(name for name in REQUEST_ORDER if name in missing)
        findings.append(
            Finding(
                RefusalCode.SECTION_NOT_IN_TEMPLATE,
                f"the template sets nothing in {names}, so there is nothing to compare.",
            )
        )
    if full and inputs.preset in SLOW_PRESETS:
        findings.append(
            Finding(
                RefusalCode.FULL_DIFF_ON_SLOW_PRESET,
                f"a full diff on {inputs.preset} is refused by policy (a typical template costs a "
                "relay several times its polite share there); name the sections to read with "
                "--section.",
            )
        )
    wanted = (
        inputs.template_sections if full else inputs.requested_sections & inputs.template_sections
    )
    if "security" in wanted and not traits.private_key_redacted:
        wanted = wanted - {"security"}
        if inputs.destination.found:
            findings.append(_security_finding(node, traits, full=full))
    return wanted, tuple(findings)


def _security_finding(node: str, traits: FirmwareTraits, *, full: bool) -> Finding:
    """Why ``security`` is left out: a note on a full diff, a refusal when it was named."""
    redacted = _dotted(PRIVATE_KEY_REDACTED_MIN_FIRMWARE)
    leak = f"the reply carries {node}'s private key over the mesh"
    if traits.version is None:
        skipped = refused = f"{node}'s firmware version is unknown, and below {redacted} {leak}"
    else:
        skipped = f"below firmware {redacted} {leak}"
        refused = f"below it {leak}"
    if full:
        return Finding(NoteCode.SECURITY_SKIPPED, f"security is not read: {skipped}.")
    return Finding(
        RefusalCode.SECURITY_BELOW_2_8,
        f"security is read only from firmware {redacted} on; {refused}.",
    )


def _kind(section: str) -> RequestKind:
    if section == "metadata":
        return RequestKind.METADATA
    if section == "owner":
        return RequestKind.OWNER
    if section == "default_channel":
        return RequestKind.CHANNEL
    if section in _CONFIG_REQUESTS:
        return RequestKind.CONFIG
    return RequestKind.MODULE


def _reply(section: str) -> tuple[int, ReplySize]:
    if section == "security":
        return SECURITY_REPLY_BYTES, ReplySize.ESTIMATED
    if section in MEASURED_REPLY_BYTES:
        return MEASURED_REPLY_BYTES[section], ReplySize.MEASURED
    return MAX_REPLY_BYTES, ReplySize.MAXIMUM


def _requests(wanted: frozenset[str]) -> tuple[Request, ...]:
    return tuple(
        Request(section, _kind(section), *_reply(section))
        for section in REQUEST_ORDER
        if section == "metadata" or section in wanted
    )


def _authorization(
    dest: Destination, gateway: Gateway
) -> tuple[GatewayAuthorization, Finding | None]:
    node = dest.label
    gw = gateway.label
    if gw == node:
        return (
            GatewayAuthorization.NO_RECORD,
            Finding(
                RefusalCode.GATEWAY_IS_DESTINATION,
                f"--gateway names {node} itself; the gateway is the radio that would send "
                "the requests.",
            ),
        )
    if not gateway.found or gateway.archived:
        return (
            GatewayAuthorization.NO_RECORD,
            Finding(
                RefusalCode.GATEWAY_NOT_IN_DATABASE,
                f"the gateway {gw} is not an active database node, so its key cannot be checked.",
            ),
        )
    if gateway.public_key is None:
        return (
            GatewayAuthorization.KEY_UNKNOWN,
            Finding(
                RefusalCode.GATEWAY_KEY_UNKNOWN,
                f"the database records no public key for the gateway {gw}; `mesh adopt` or "
                "`mesh provision` records it over a local link.",
            ),
        )
    if not dest.found:
        return GatewayAuthorization.NO_RECORD, None
    if gateway.public_key in dest.authorized_keys:
        return GatewayAuthorization.AUTHORIZED, None
    return (
        GatewayAuthorization.NOT_AUTHORIZED,
        Finding(
            RefusalCode.GATEWAY_NOT_AUTHORIZED,
            f"{node}'s recorded admin keys do not include the gateway {gw}'s key; it would "
            "refuse the gateway's requests.",
        ),
    )


def _gateway_findings(
    inputs: DryRunInputs,
) -> tuple[GatewayAuthorization, int, tuple[Finding, ...]]:
    node = inputs.destination.label
    gateway = inputs.gateway
    if gateway is None:
        return (
            GatewayAuthorization.NOT_CHECKED,
            GATEWAY_ATTEMPTS_FROM_2_8,
            (
                Finding(
                    NoteCode.GATEWAY_ASSUMED,
                    f"no --gateway: whether the gateway may administer {node} is not checked, "
                    f"and {GATEWAY_ATTEMPTS_FROM_2_8} transmissions are charged for each "
                    "unanswered request.",
                ),
            ),
        )
    traits = firmware_traits(gateway.firmware)
    authorization, finding = _authorization(inputs.destination, gateway)
    findings = [] if finding is None else [finding]
    if gateway.found and traits.version is None:
        findings.append(
            Finding(
                NoteCode.GATEWAY_ASSUMED,
                f"the gateway {gateway.label}'s recorded firmware version does not parse; "
                f"{GATEWAY_ATTEMPTS_FROM_2_8} transmissions are charged for each unanswered "
                "request.",
            )
        )
    return authorization, traits.unicast_attempts, tuple(findings)


def _busy_findings(dest: Destination, *, region_ok: bool) -> tuple[Finding, ...]:
    if not dest.found:
        return ()
    reading = dest.air_util_tx
    if reading is None or reading.age_seconds > BUSY_EVIDENCE_MAX_AGE_SECONDS:
        hours = BUSY_EVIDENCE_MAX_AGE_SECONDS / 3600
        return (
            Finding(
                NoteCode.BUSY_UNKNOWN,
                f"no transmit air utilization for {dest.label} from the last {hours:g} hours "
                "in the local health history (`mesh health` refreshes it); its own load is "
                "unknown.",
            ),
        )
    duty = REGION_BANDS[MODELLED_REGION].duty_cycle
    threshold = duty * BUSY_SHARE_OF_DUTY
    if region_ok and reading.percent > threshold:
        return (
            Finding(
                RefusalCode.DESTINATION_BUSY,
                f"{dest.label} reported transmitting {reading.percent:.2f} % of its last hour "
                f"{reading.age_seconds / 60:.0f} min ago, above {threshold:g} % (half of "
                f"{MODELLED_REGION}'s {duty:g} % limit); near its limit its firmware drops "
                "its own replies, and every relay's airtime on the requests is wasted.",
            ),
        )
    return ()


def _never_written(requests: tuple[Request, ...]) -> Finding | None:
    read = {request.section for request in requests}
    keys = [key for key in REFUSED_CONFIG if key.split(".", 1)[0] in read]
    if not keys:
        return None
    return Finding(
        NoteCode.NEVER_WRITTEN,
        "mesh has no remote write: a difference is fixed over a local link with `mesh "
        f"provision`. Of what this diff reads, remote work never writes {', '.join(keys)}.",
    )


def _timings(
    preset: str, slot: int, settle: SettleRule, count: int, links: int
) -> tuple[LinkTiming, ...]:
    timings = []
    for link in range(1, links + 1):
        typical = deadline_seconds(preset, link, slot_ms=slot, cw=TYPICAL_CW)
        worst = deadline_seconds(preset, link, slot_ms=slot, cw=WORST_CASE_CW)
        timings.append(
            LinkTiming(
                links=link,
                deadline_typical=typical,
                deadline_worst_case=worst,
                longest_run_typical=settle.max_seconds + count * typical,
                longest_run_worst_case=settle.max_seconds + count * worst,
            )
        )
    return tuple(timings)


def _share_findings(ledger: Ledger, worst: Ledger, region: str) -> tuple[Finding, ...]:
    budget = ledger.budget_seconds
    if budget is None:
        return ()
    if not ledger.fits:
        duty = REGION_BANDS[MODELLED_REGION].duty_cycle
        return (
            Finding(
                RefusalCode.OVER_POLITE_SHARE,
                f"one relay would spend {ledger.relay_seconds:.2f} s of airtime on this diff "
                f"at contention window {TYPICAL_CW}, over the polite share of {budget:.2f} s "
                f"per rolling hour ({POLITE_RELAY_SHARE * 100:g} % of a relay's legal "
                f"{HOUR_SECONDS * duty / 100:g} s on {region}, a policy, not a limit); read "
                "fewer sections with --section.",
            ),
        )
    findings = []
    if ledger.relay_largest_replies_seconds > budget:
        findings.append(
            Finding(
                NoteCode.LARGEST_REPLIES_OVER_SHARE,
                f"if every reply had the largest size ({MAX_REPLY_BYTES} B), one relay would "
                f"spend {ledger.relay_largest_replies_seconds:.2f} s at contention window "
                f"{TYPICAL_CW}, over the polite share.",
            )
        )
    if not worst.fits:
        findings.append(
            Finding(
                NoteCode.WORST_CASE_OVER_SHARE,
                f"at contention window {WORST_CASE_CW} on every link (strong links, SNR 10 to "
                f"15 dB) one relay would spend {worst.relay_seconds:.2f} s, over the "
                "polite share; this does not refuse the read.",
            )
        )
    return tuple(findings)


def _path_note(inputs: DryRunInputs, max_links: int) -> Finding:
    hop_limit = inputs.hop_limit
    capped = f", the model stops at {MAX_LINKS}" if hop_limit + 1 > MAX_LINKS else ""
    return Finding(
        NoteCode.PATH_UNKNOWN,
        f"the path to {inputs.destination.label} is unknown offline: deadlines and run times "
        f"are shown for 1 to {max_links} links (the template's hop limit {hop_limit} allows "
        f"{hop_limit + 1}{capped}). On a first contact every rebroadcasting node that hears a "
        "request with hops left sends it again, not only the nodes on the path; what one "
        "relay pays does not depend on the path, how many pay is unknown.",
    )


def _estimate(
    inputs: DryRunInputs, preset: str, requests: tuple[Request, ...], attempts: int
) -> tuple[Estimate, tuple[Finding, ...]]:
    slot = slot_ms(preset, PATH_CAD_SYMBOLS)
    settle = settle_rule(preset)
    max_links = min(inputs.hop_limit + 1, MAX_LINKS)
    sizes = [request.reply_bytes for request in requests]
    ledger = diff_ledger(
        preset, inputs.region, sizes, slot_ms=slot, cw=TYPICAL_CW, gateway_attempts=attempts
    )
    worst = diff_ledger(
        preset, inputs.region, sizes, slot_ms=slot, cw=WORST_CASE_CW, gateway_attempts=attempts
    )
    estimate = Estimate(
        region=inputs.region,
        preset=preset,
        slot_ms=slot,
        settle=settle,
        timings=_timings(preset, slot, settle, len(requests), max_links),
        ledger=ledger,
        ledger_worst_case=worst,
    )
    findings = (*_share_findings(ledger, worst, inputs.region), _path_note(inputs, max_links))
    return estimate, findings


def _sorted(
    findings: Iterable[Finding],
) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
    ordered = sorted(findings, key=lambda finding: _CODE_ORDER[finding.code])
    return (
        tuple(f for f in ordered if isinstance(f.code, RefusalCode)),
        tuple(f for f in ordered if isinstance(f.code, NoteCode)),
    )


def _validate(inputs: DryRunInputs) -> None:
    if not 0 <= inputs.hop_limit <= _MAX_HOP_LIMIT:
        raise ValueError(f"hop_limit must be 0..{_MAX_HOP_LIMIT}, got {inputs.hop_limit}")
    for label, names in (
        ("template_sections", inputs.template_sections),
        ("requested_sections", inputs.requested_sections),
    ):
        unknown = sorted(set(names) - set(SECTION_CHOICES))
        if unknown:
            raise ValueError(f"{label} has unknown sections: {', '.join(unknown)}")
    reading = inputs.destination.air_util_tx
    if reading is not None and reading.age_seconds < 0:
        raise ValueError(f"air_util_tx.age_seconds must not be negative, got {reading.age_seconds}")


def plan_dry_run(inputs: DryRunInputs) -> DryRunPlan:
    """Plan a read-only diff of one node from plain facts, sending nothing.

    Args:
        inputs: The facts about the destination, the gateway and the template.

    Returns:
        The plan: requests, refusals, notes and the modelled cost.

    Raises:
        ValueError: If an input is out of range (a programming error, not a refusal).
    """
    _validate(inputs)
    dest = inputs.destination
    traits = firmware_traits(dest.firmware)
    region_ok = inputs.region == MODELLED_REGION
    preset_ok = inputs.preset is not None and inputs.preset in PRESET_RADIO
    wanted, section_findings = _sections(inputs, traits)
    requests = _requests(wanted)
    authorization, attempts, gateway_findings = _gateway_findings(inputs)
    findings = [
        *_destination_findings(dest, traits),
        *_model_findings(inputs),
        *section_findings,
        *gateway_findings,
        *_busy_findings(dest, region_ok=region_ok),
    ]
    estimate = None
    if region_ok and preset_ok and inputs.preset is not None:
        estimate, estimate_findings = _estimate(inputs, inputs.preset, requests, attempts)
        findings.extend(estimate_findings)
    never_written = _never_written(requests)
    if never_written is not None:
        findings.append(never_written)
    refusals, notes = _sorted(findings)
    return DryRunPlan(
        destination=dest.label,
        gateway=None if inputs.gateway is None else inputs.gateway.label,
        full_diff=not inputs.requested_sections,
        firmware_recorded=dest.firmware,
        firmware_version=traits.version,
        security_read="security" in wanted,
        gateway_authorization=authorization,
        gateway_attempts=attempts,
        air_util_tx=dest.air_util_tx,
        requests=requests,
        refusals=refusals,
        notes=notes,
        estimate=estimate,
    )
