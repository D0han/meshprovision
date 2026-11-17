"""The enums and dataclasses of an offline remote diff plan.

What :func:`~meshprovision.remote.plan.plan_dry_run` takes (the facts about the destination,
the gateway and the template) and returns (the requests, refusals, notes and the modelled
cost). Pure data: no rule lives here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from meshprovision.remote.budget import SettleRule
from meshprovision.remote.ledger import Ledger

__all__ = [
    "AirUtilReading",
    "Destination",
    "DryRunInputs",
    "DryRunPlan",
    "Estimate",
    "Finding",
    "Gateway",
    "GatewayAuthorization",
    "LinkTiming",
    "NoteCode",
    "RefusalCode",
    "ReplySize",
    "Request",
    "RequestKind",
    "Verdict",
]


class RequestKind(StrEnum):
    """What one request asks for.

    The AdminMessage variants are ``get_device_metadata_request``, ``get_owner_request``,
    ``get_config_request``, ``get_module_config_request`` and ``get_channel_request`` with
    index 0.
    """

    METADATA = "metadata"
    OWNER = "owner"
    CONFIG = "config"
    MODULE = "module"
    CHANNEL = "channel"


class ReplySize(StrEnum):
    """Where a planned reply's size comes from."""

    MEASURED = "measured"  # a simulator run's reply
    ESTIMATED = "estimated"  # derived from a measured reply
    MAXIMUM = "maximum"  # the largest packet, for a section no run read


class Verdict(StrEnum):
    """What the offline rules say."""

    ALLOWED = "allowed"  # every rule this version can check offline passes
    REFUSED = "refused"  # at least one refusal


class GatewayAuthorization(StrEnum):
    """What the database says about the gateway's key in the destination's admin list."""

    NOT_CHECKED = "not_checked"  # no --gateway
    AUTHORIZED = "authorized"
    NOT_AUTHORIZED = "not_authorized"
    KEY_UNKNOWN = "key_unknown"  # the gateway's row has no recorded public key
    NO_RECORD = "no_record"  # the gateway or the destination has no usable row, or the
    # gateway is the destination


class RefusalCode(StrEnum):
    """Why the plan refuses the read; declaration order is report order."""

    NOT_IN_DATABASE = "not_in_database"
    ARCHIVED = "archived"
    NOT_TEMPLATE_MANAGED = "not_template_managed"
    FIRMWARE_UNKNOWN = "firmware_unknown"
    FIRMWARE_TOO_OLD = "firmware_too_old"
    REGION_NOT_MODELLED = "region_not_modelled"
    PRESET_NOT_MODELLED = "preset_not_modelled"
    OVERRIDE_DUTY_CYCLE = "override_duty_cycle"
    SECTION_NOT_IN_TEMPLATE = "section_not_in_template"
    FULL_DIFF_ON_SLOW_PRESET = "full_diff_on_slow_preset"
    SECURITY_BELOW_2_8 = "security_below_2_8"
    GATEWAY_IS_DESTINATION = "gateway_is_destination"
    GATEWAY_NOT_IN_DATABASE = "gateway_not_in_database"
    GATEWAY_KEY_UNKNOWN = "gateway_key_unknown"
    GATEWAY_NOT_AUTHORIZED = "gateway_not_authorized"
    DESTINATION_BUSY = "destination_busy"
    OVER_POLITE_SHARE = "over_polite_share"


class NoteCode(StrEnum):
    """What the plan tells the reader without refusing; declaration order is report order."""

    PATH_UNKNOWN = "path_unknown"
    GATEWAY_ASSUMED = "gateway_assumed"
    SECURITY_SKIPPED = "security_skipped"
    ADMIN_KEY_FALLBACK = "admin_key_fallback"
    TWO_FREQUENCY_SLOTS = "two_frequency_slots"
    BUSY_UNKNOWN = "busy_unknown"
    LARGEST_REPLIES_OVER_SHARE = "largest_replies_over_share"
    WORST_CASE_OVER_SHARE = "worst_case_over_share"
    NEVER_WRITTEN = "never_written"


@dataclass(frozen=True, slots=True)
class Finding:
    """One refusal or note.

    Attributes:
        code: The refusal or note code.
        message: The sentence shown to the user.
    """

    code: RefusalCode | NoteCode
    message: str


@dataclass(frozen=True, slots=True)
class AirUtilReading:
    """The destination's last-known transmit air utilisation.

    Attributes:
        percent: The reading, in percent of the last hour.
        age_seconds: How long ago it was taken, 0 or more.
    """

    percent: float
    age_seconds: float


@dataclass(frozen=True, slots=True)
class Destination:
    """What the database and the health history say about the node to read.

    Attributes:
        label: The ``!hex`` display form of the node id.
        found: The database has a row for it.
        archived: The row is archived.
        template_managed: The row's management is ``template`` (enrolled).
        firmware: The recorded firmware version string, or ``""``.
        authorized_keys: The raw public keys the node's ``authorized_admin_keys`` refs
            resolve to in the Keys sheet: last-known, never read off the device.
        air_util_tx: The newest recorded transmit air utilisation, if any.
    """

    label: str
    found: bool
    archived: bool = False
    template_managed: bool = False
    firmware: str = ""
    authorized_keys: frozenset[bytes] = frozenset()
    air_util_tx: AirUtilReading | None = None


@dataclass(frozen=True, slots=True)
class Gateway:
    """What the database says about the radio that would send the requests.

    Attributes:
        label: The ``!hex`` display form of the node id.
        found: The database has a row for it.
        archived: The row is archived.
        firmware: The recorded firmware version string, or ``""``.
        public_key: The gateway row's own ``<hex>_pub`` key, if one is recorded.
    """

    label: str
    found: bool
    archived: bool = False
    firmware: str = ""
    public_key: bytes | None = None


@dataclass(frozen=True, slots=True)
class DryRunInputs:
    """Everything :func:`plan_dry_run` needs, as plain facts.

    Attributes:
        destination: The node to read.
        gateway: The gateway, or ``None`` when ``--gateway`` is not given.
        region: The template's region.
        preset: The template's modem preset, or ``None`` when it runs none.
        hop_limit: The template's hop limit.
        override_duty_cycle: The template sets ``lora.override_duty_cycle``.
        template_sections: The sections the template sets (see :func:`template_sections`).
        requested_sections: The ``--section`` names; empty means a full diff.
    """

    destination: Destination
    gateway: Gateway | None
    region: str
    preset: str | None
    hop_limit: int
    override_duty_cycle: bool
    template_sections: frozenset[str]
    requested_sections: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class Request:
    """One planned request and the reply it expects.

    Attributes:
        section: The section it reads (``metadata`` for the firmware version).
        kind: What kind of AdminMessage asks for it.
        reply_bytes: The reply's size on air.
        reply_size: Where :attr:`reply_bytes` comes from.
    """

    section: str
    kind: RequestKind
    reply_bytes: int
    reply_size: ReplySize


@dataclass(frozen=True, slots=True)
class LinkTiming:
    """Deadlines and run times for one link count.

    Attributes:
        links: The number of links to the node.
        deadline_typical: One request's deadline at ``TYPICAL_CW``.
        deadline_worst_case: One request's deadline at ``WORST_CASE_CW``.
        longest_run_typical: The settle maximum plus every request running to its
            deadline, at ``TYPICAL_CW``.
        longest_run_worst_case: The same at ``WORST_CASE_CW``.
    """

    links: int
    deadline_typical: float
    deadline_worst_case: float
    longest_run_typical: float
    longest_run_worst_case: float


@dataclass(frozen=True, slots=True)
class Estimate:
    """The modelled cost of the plan.

    Attributes:
        region: The region.
        preset: The modem preset.
        slot_ms: The relays' assumed slot time.
        settle: How long to listen before the first request.
        timings: One entry per link count the hop limit allows.
        ledger: The airtime at ``TYPICAL_CW``, which decides the verdict.
        ledger_worst_case: The airtime at ``WORST_CASE_CW``, shown only.
    """

    region: str
    preset: str
    slot_ms: int
    settle: SettleRule
    timings: tuple[LinkTiming, ...]
    ledger: Ledger
    ledger_worst_case: Ledger


@dataclass(frozen=True, slots=True)
class DryRunPlan:
    """The offline plan of one remote diff.

    Attributes:
        destination: The node's ``!hex`` label.
        gateway: The gateway's label, or ``None``.
        full_diff: No ``--section`` was given.
        firmware_recorded: The recorded firmware string, or ``""``.
        firmware_version: The parsed version, or ``None``.
        security_read: The ``security`` section is among the requests.
        gateway_authorization: What the database says about the gateway's key.
        gateway_attempts: The gateway's transmissions charged per unanswered request.
        air_util_tx: The destination's last-known transmit air utilisation, if any.
        requests: The requests, the metadata first.
        refusals: The refusals, in code order.
        notes: The notes, in code order.
        estimate: The modelled cost, or ``None`` when the region or preset is outside the
            model.
    """

    destination: str
    gateway: str | None
    full_diff: bool
    firmware_recorded: str
    firmware_version: tuple[int, int, int] | None
    security_read: bool
    gateway_authorization: GatewayAuthorization
    gateway_attempts: int
    air_util_tx: AirUtilReading | None
    requests: tuple[Request, ...]
    refusals: tuple[Finding, ...]
    notes: tuple[Finding, ...]
    estimate: Estimate | None

    @property
    def verdict(self) -> Verdict:
        """``REFUSED`` when any refusal stands, else ``ALLOWED``."""
        return Verdict.REFUSED if self.refusals else Verdict.ALLOWED
