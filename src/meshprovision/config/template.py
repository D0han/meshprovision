"""The provisioning template model.

Validates ``config/template.yaml`` (or any template YAML) into a
:class:`TemplateConfig`: module options, the ``{n}``-placeholder name
patterns used to generate ``short_name``/``long_name`` for new nodes,
0-3 admin node references, and the ``lora``/``position``/``power``/
``telemetry``/``device``/``security`` config sections applied at
provisioning time.

The name-pattern machinery lives in :class:`PatternSpec`: it compiles a
pattern into literal/slot segments without ever using ``str.format`` (an
operator-supplied pattern is not a trusted format string), computes the
namespace's capacity, and renders or parses names against it. Because
the Meshtastic firmware *silently truncates* an over-length name rather
than rejecting it, byte-length overflow is a hard validation error at
template-load time, not a runtime surprise.

``pydantic-v2`` note (also documented on :func:`load_template_text`):
:class:`~meshprovision.errors.MeshprovisionError` is a plain ``Exception``,
not a ``ValueError``, so raising one inside a validator propagates *out*
of ``model_validate`` unchanged rather than being folded into a
``pydantic.ValidationError``. That is deliberate here -- it is what lets
a :class:`~meshprovision.errors.NamePatternError` reach the caller with
its ``pattern``/``byte_length``/``limit`` fields intact instead of being
flattened into a generic validation message. Every loader in this module
therefore catches ``pydantic.ValidationError`` and ``MeshprovisionError``
in separate ``except`` clauses, re-raising the latter untouched.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from meshprovision.config.settings import format_validation_error
from meshprovision.enums import region_table, role_table
from meshprovision.errors import (
    MAX_ADMIN_KEYS,
    AdminKeyCapacityError,
    NameCapacityError,
    NamePatternError,
    NamespaceExhaustedError,
    TemplateValidationError,
)

__all__ = [
    "BASE36_ALPHABET",
    "DEFAULT_MIN_CAPACITY",
    "DEFAULT_WARN_UTILIZATION",
    "KNOWN_MODULE_OPTIONS",
    "LONG_NAME_MAX_BYTES",
    "SHORT_NAME_MAX_BYTES",
    "SUFFIX_TOKEN",
    "DeviceSection",
    "LoraSection",
    "PatternSpec",
    "PositionSection",
    "PowerSection",
    "SecuritySection",
    "TelemetrySection",
    "TemplateConfig",
    "TemplateWarning",
    "admin_private_key_ref",
    "admin_public_key_ref",
    "check_capacity_utilization",
    "ensure_capacity_available",
    "load_template",
    "load_template_text",
]

_logger = logging.getLogger(__name__)

SHORT_NAME_MAX_BYTES: Final[int] = 4
"""Firmware limit on ``short_name``, in UTF-8 bytes. Silently truncated
past this length rather than rejected."""

LONG_NAME_MAX_BYTES: Final[int] = 39
"""Firmware limit on ``long_name``, in UTF-8 bytes. Silently truncated
past this length rather than rejected."""

BASE36_ALPHABET: Final[str] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"""Default ``name_suffix_alphabet``: the 36 upper-case base36 digits."""

SUFFIX_TOKEN: Final[str] = "{n}"  # noqa: S105 -- a placeholder token, not a password
"""The only placeholder token a name pattern may contain."""

DEFAULT_MIN_CAPACITY: Final[int] = 100
"""Default floor for :attr:`TemplateConfig.name_min_capacity`."""

DEFAULT_WARN_UTILIZATION: Final[float] = 0.9
"""Default namespace-utilization ratio at which a warning is raised."""

KNOWN_MODULE_OPTIONS: Final[frozenset[str]] = frozenset(
    {
        "mqtt",
        "serial",
        "external_notification",
        "store_forward",
        "range_test",
        "telemetry",
        "canned_message",
        "audio",
        "remote_hardware",
        "neighbor_info",
        "ambient_lighting",
        "detection_sensor",
        "paxcounter",
    }
)
"""Module option names meshprovision recognizes. An option outside this
set is not an error -- firmware adds modules over time -- but produces a
:class:`TemplateWarning`."""

_ADMIN_REF_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_KEY_MATERIAL_KEYS: Final[frozenset[str]] = frozenset(
    {"private_key", "public_key", "admin_key", "adminKey"}
)


@dataclass(frozen=True, slots=True)
class TemplateWarning:
    """A non-fatal finding surfaced by :meth:`TemplateConfig.collect_warnings`.

    Attributes:
        code: Machine-readable warning code, one of
            ``"capacity_below_floor"``, ``"capacity_near_exhaustion"``,
            ``"unknown_option"``, or ``"long_name_near_limit"``.
        message: Human-readable description of the finding.
        field: Name of the associated template field, when known.
    """

    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """A compiled ``{n}``-placeholder name pattern.

    Never uses ``str.format``/``str.format_map`` -- an operator-supplied
    pattern is treated as untrusted input, not a trusted format string --
    so compilation hand-scans the pattern instead.

    Attributes:
        pattern: The original, uncompiled pattern string.
        alphabet: The suffix alphabet; each character is one possible
            digit for a ``{n}`` slot.
        literals: The literal text segments surrounding each slot.
            Length is always ``slot_count + 1``: ``literals[i]`` precedes
            slot ``i``, and ``literals[-1]`` trails the final slot.
        field: Name of the template field this pattern came from, used
            to make error messages actionable.
    """

    pattern: str
    alphabet: str
    literals: tuple[str, ...]
    field: str

    @property
    def slot_count(self) -> int:
        """Return the number of ``{n}`` slots in the pattern.

        Returns:
            ``len(literals) - 1``.
        """
        return len(self.literals) - 1

    @property
    def capacity(self) -> int:
        """Return the total number of distinct names this pattern can render.

        Returns:
            ``len(alphabet) ** slot_count``.
        """
        return int(len(self.alphabet) ** self.slot_count)

    def render(self, index: int) -> str:
        """Render the name at the given index.

        Args:
            index: A zero-based index into the pattern's namespace.

        Returns:
            The rendered name: each ``{n}`` slot replaced by the
            base-``len(alphabet)`` digits of ``index``, most-significant
            first, zero-padded (with ``alphabet[0]``) to ``slot_count``
            digits.

        Raises:
            NamespaceExhaustedError: If ``index`` is negative or
                ``>= capacity``.
        """
        capacity = self.capacity
        if index < 0 or index >= capacity:
            raise NamespaceExhaustedError(
                f"Index {index} is out of range for pattern {self.pattern!r} "
                f"(capacity {capacity}).",
                pattern=self.pattern,
                capacity=capacity,
            )
        base = len(self.alphabet)
        digits: list[str] = []
        remaining = index
        for _ in range(self.slot_count):
            remaining, digit_index = divmod(remaining, base)
            digits.append(self.alphabet[digit_index])
        digits.reverse()
        parts: list[str] = [self.literals[0]]
        for slot_index, digit in enumerate(digits):
            parts.append(digit)
            parts.append(self.literals[slot_index + 1])
        return "".join(parts)

    def render_widest(self) -> str:
        """Render the widest-possible name (in UTF-8 bytes) this pattern can produce.

        Every slot is filled with whichever alphabet character encodes
        to the most UTF-8 bytes -- not necessarily the last character in
        the alphabet.

        Returns:
            The widest rendering.
        """
        widest_char = max(self.alphabet, key=lambda c: len(c.encode("utf-8")))
        parts: list[str] = [self.literals[0]]
        for slot_index in range(self.slot_count):
            parts.append(widest_char)
            parts.append(self.literals[slot_index + 1])
        return "".join(parts)

    def widest_byte_length(self) -> int:
        """Return the UTF-8 byte length of :meth:`render_widest`.

        Returns:
            The byte length of the widest possible rendering.
        """
        return len(self.render_widest().encode("utf-8"))

    def parse_index(self, name: str) -> int | None:
        """Recover the index that would render as ``name``, if any.

        The exact inverse of :meth:`render`: for every ``i`` in
        ``range(capacity)``, ``parse_index(render(i)) == i``.

        Args:
            name: A candidate rendered name.

        Returns:
            The recovered index, or ``None`` if ``name`` does not fit
            this pattern (wrong prefix, unknown alphabet character, or
            leftover text). Never raises.
        """
        pos = 0
        digits: list[int] = []
        for slot_index in range(self.slot_count):
            prefix = self.literals[slot_index]
            if not name.startswith(prefix, pos):
                return None
            pos += len(prefix)
            if pos >= len(name):
                return None
            digit_index = self.alphabet.find(name[pos])
            if digit_index == -1:
                return None
            digits.append(digit_index)
            pos += 1
        trailing = self.literals[-1]
        if not name.startswith(trailing, pos) or pos + len(trailing) != len(name):
            return None
        base = len(self.alphabet)
        value = 0
        for digit in digits:
            value = value * base + digit
        return value

    def iter_names(self, start: int = 0) -> Iterator[str]:
        """Iterate every name this pattern can render, from ``start``.

        Args:
            start: Index to begin iterating from.

        Yields:
            Each rendered name, in ascending index order.
        """
        for index in range(start, self.capacity):
            yield self.render(index)

    @classmethod
    def compile(cls, pattern: str, alphabet: str, *, field: str) -> PatternSpec:
        """Compile a ``{n}``-placeholder pattern against a suffix alphabet.

        Args:
            pattern: The pattern string. ``{n}`` is the only supported
                placeholder; a literal brace is written ``{{`` or ``}}``.
            alphabet: The suffix alphabet: non-empty, no duplicate
                characters, no whitespace, and no ``{``/``}``.
            field: Name of the template field this pattern came from,
                used to make error messages actionable.

        Returns:
            The compiled :class:`PatternSpec`.

        Raises:
            TemplateValidationError: If ``pattern`` is empty, contains
                an unsupported placeholder or an unmatched brace, or if
                ``alphabet`` violates any of its rules.
        """
        _validate_alphabet(alphabet)
        if not pattern:
            raise TemplateValidationError(f"{field} must not be empty.", field=field)

        i = 0
        literal: list[str] = []
        literals: list[str] = []
        while i < len(pattern):
            if pattern.startswith("{{", i):
                literal.append("{")
                i += 2
            elif pattern.startswith("}}", i):
                literal.append("}")
                i += 2
            elif pattern.startswith(SUFFIX_TOKEN, i):
                literals.append("".join(literal))
                literal.clear()
                i += len(SUFFIX_TOKEN)
            elif pattern[i] == "{":
                raise TemplateValidationError(
                    f"Unsupported placeholder in {field}: {pattern!r}. The only "
                    "supported placeholder is '{n}'; write a literal brace as "
                    "'{{' or '}}'.",
                    field=field,
                )
            elif pattern[i] == "}":
                raise TemplateValidationError(
                    f"Unmatched '}}' in {field}: {pattern!r}.",
                    field=field,
                )
            else:
                literal.append(pattern[i])
                i += 1
        literals.append("".join(literal))

        return cls(pattern=pattern, alphabet=alphabet, literals=tuple(literals), field=field)


def _validate_alphabet(alphabet: str) -> None:
    """Validate a ``name_suffix_alphabet`` value.

    Args:
        alphabet: The candidate alphabet string.

    Raises:
        TemplateValidationError: If the alphabet is empty, contains
            duplicate characters, contains whitespace, or contains
            ``{``/``}``.
    """
    if not alphabet:
        raise TemplateValidationError(
            "name_suffix_alphabet must not be empty.", field="name_suffix_alphabet"
        )
    seen: set[str] = set()
    duplicates: set[str] = set()
    for ch in alphabet:
        if ch in seen:
            duplicates.add(ch)
        seen.add(ch)
    if duplicates:
        dup_str = ", ".join(repr(c) for c in sorted(duplicates))
        raise TemplateValidationError(
            f"name_suffix_alphabet contains duplicate character(s): {dup_str}.",
            field="name_suffix_alphabet",
        )
    if any(ch.isspace() for ch in alphabet):
        raise TemplateValidationError(
            "name_suffix_alphabet must not contain whitespace.",
            field="name_suffix_alphabet",
        )
    if "{" in alphabet or "}" in alphabet:
        raise TemplateValidationError(
            "name_suffix_alphabet must not contain '{' or '}'.",
            field="name_suffix_alphabet",
        )


def admin_public_key_ref(ref: str) -> str:
    """Build the Keys-sheet reference for an admin node's public key.

    Args:
        ref: The admin node reference, as it appears in ``admin_nodes``.

    Returns:
        ``f"{ref}_pub"``.
    """
    return f"{ref}_pub"


def admin_private_key_ref(ref: str) -> str:
    """Build the Keys-sheet reference for an admin node's private key.

    Args:
        ref: The admin node reference, as it appears in ``admin_nodes``.

    Returns:
        ``f"{ref}_priv"``.
    """
    return f"{ref}_priv"


def check_capacity_utilization(
    spec: PatternSpec, used: int, *, warn_at: float = DEFAULT_WARN_UTILIZATION
) -> TemplateWarning | None:
    """Check a pattern's namespace utilization against a warning threshold.

    Args:
        spec: The pattern to check.
        used: The number of names from ``spec``'s namespace currently in
            use (looked up in the database; not known at template-load
            time).
        warn_at: Utilization ratio (``used / spec.capacity``) at or above
            which a warning is returned.

    Returns:
        A ``"capacity_near_exhaustion"`` :class:`TemplateWarning` when
        utilization is at or above ``warn_at``; otherwise ``None``.

    Raises:
        ValueError: If ``used`` is negative.
    """
    if used < 0:
        raise ValueError("used must not be negative")
    ratio = used / spec.capacity
    if ratio >= warn_at:
        return TemplateWarning(
            "capacity_near_exhaustion",
            f"{used} of {spec.capacity} names used ({ratio:.0%}) for pattern {spec.pattern!r}.",
            field=spec.field,
        )
    return None


def ensure_capacity_available(spec: PatternSpec, used: int) -> None:
    """Raise if a pattern's namespace has no unused names left.

    Args:
        spec: The pattern to check.
        used: The number of names from ``spec``'s namespace currently in
            use.

    Raises:
        NamespaceExhaustedError: If ``used >= spec.capacity``.
    """
    if used >= spec.capacity:
        raise NamespaceExhaustedError(
            f"Name pattern {spec.pattern!r} is exhausted: all {spec.capacity} names "
            f"over the {len(spec.alphabet)}-character alphabet are in use.",
            pattern=spec.pattern,
            capacity=spec.capacity,
            hint=(
                "Widen name_suffix_alphabet or add another {n} slot to the pattern "
                "(mind the 4-byte short_name limit)."
            ),
        )


def _normalize_str_tuple(value: object) -> tuple[str, ...]:
    """Coerce a before-validator input into a de-duplicated tuple of strings.

    Shared by ``enabled_options``, ``disabled_options``, and
    ``admin_nodes``: ``None`` becomes ``()``; each element must be a
    string, is stripped, and empties are dropped; duplicates (after
    stripping) are rejected.

    Args:
        value: The raw field value.

    Returns:
        A tuple of non-empty, stripped strings.

    Raises:
        ValueError: If ``value`` is not a list/tuple, contains a
            non-string element, or contains duplicate entries. Pydantic
            folds this into the field's ``ValidationError`` entry, which
            is the one place in this module a bare ``ValueError`` is the
            correct exception to raise.
    """
    if value is None:
        return ()
    if not isinstance(value, list | tuple):
        raise ValueError("must be a list of strings")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"expected a string, got {item!r}")
        stripped = item.strip()
        if stripped:
            items.append(stripped)
    seen: set[str] = set()
    duplicates: list[str] = []
    for item in items:
        if item in seen and item not in duplicates:
            duplicates.append(item)
        seen.add(item)
    if duplicates:
        raise ValueError(f"duplicate entries: {', '.join(sorted(duplicates))}")
    return tuple(items)


class DeviceSection(BaseModel):
    """``config.device`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.DeviceConfig`` message.

    Attributes:
        role: Device role name, validated against
            :func:`meshprovision.enums.role_table`.
        rebroadcast_mode: Rebroadcast mode name, passed through
            unvalidated; provisioning maps it to the protobuf enum.
        node_info_broadcast_secs: Node-info broadcast interval, seconds.
        button_gpio: GPIO pin number for the user button, when overridden.
        buzzer_gpio: GPIO pin number for the buzzer, when overridden.
        double_tap_as_button_press: Whether an accelerometer double-tap
            counts as a button press.
        disable_triple_click: Whether the triple-click gesture is disabled.
        led_heartbeat_disabled: Whether the heartbeat LED is disabled.
        tzdef: POSIX timezone definition string.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: str = "CLIENT"
    rebroadcast_mode: str | None = None
    node_info_broadcast_secs: int | None = Field(default=None, ge=0)
    button_gpio: int | None = Field(default=None, ge=0)
    buzzer_gpio: int | None = Field(default=None, ge=0)
    double_tap_as_button_press: bool | None = None
    disable_triple_click: bool | None = None
    led_heartbeat_disabled: bool | None = None
    tzdef: str | None = None


class LoraSection(BaseModel):
    """``config.lora`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.LoRaConfig`` message.

    Attributes:
        region: LoRa region name, validated against
            :func:`meshprovision.enums.region_table`. Defaults to
            ``"EU_868"`` -- the Meshtastic ``RegionCode`` covering Poland;
            there is no ``"PL"`` region code in the protobuf.
        use_preset: Whether ``modem_preset`` governs the radio parameters
            (as opposed to manual bandwidth/spread-factor/coding-rate).
        modem_preset: Modem preset name, when ``use_preset`` is true.
        hop_limit: Maximum mesh hop count, 0-7.
        tx_enabled: Whether the radio is allowed to transmit.
        tx_power: Transmit power override, in dBm, when set.
        channel_num: LoRa channel number override, when set.
        frequency_offset: Frequency offset, in Hz, when set.
        override_duty_cycle: Whether the regional duty-cycle limit is
            overridden.
        sx126x_rx_boosted_gain: Whether SX126x boosted RX gain is enabled.
        ignore_mqtt: Whether MQTT-originated packets are ignored on this
            radio.
        config_ok_to_mqtt: Whether the operator has consented to this
            node's traffic being relayed to MQTT.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    region: str = "EU_868"
    use_preset: bool = True
    modem_preset: str | None = "LONG_FAST"
    hop_limit: int = Field(default=3, ge=0, le=7)
    tx_enabled: bool = True
    tx_power: int | None = Field(default=None, ge=0, le=30)
    channel_num: int | None = Field(default=None, ge=0)
    frequency_offset: float | None = None
    override_duty_cycle: bool = False
    sx126x_rx_boosted_gain: bool | None = None
    ignore_mqtt: bool | None = None
    config_ok_to_mqtt: bool | None = None


class PositionSection(BaseModel):
    """``config.position`` fields applied at provisioning time.

    Field names and types (except ``fixed_latitude``/``fixed_longitude``/
    ``fixed_altitude``, see below) are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.PositionConfig`` message.

    Attributes:
        position_broadcast_secs: Position broadcast interval, seconds.
        position_broadcast_smart_enabled: Whether smart (distance/time
            gated) position broadcasting is enabled.
        fixed_position: Whether this node's position is fixed rather than
            GPS-tracked.
        gps_update_interval: GPS fix update interval, seconds.
        position_flags: Bitmask of which position fields to include in
            broadcasts.
        broadcast_smart_minimum_distance: Minimum movement, meters, before
            a smart broadcast fires.
        broadcast_smart_minimum_interval_secs: Minimum time between smart
            broadcasts, seconds.
        gps_mode: GPS mode name (enabled/disabled/not-present).
        fixed_latitude: Fixed-position latitude, degrees. Not a
            ``PositionConfig`` field -- applied via the device's
            fixed-position API, not via ``config.position``.
        fixed_longitude: Fixed-position longitude, degrees. Applied the
            same way as ``fixed_latitude``.
        fixed_altitude: Fixed-position altitude, meters. Applied the same
            way as ``fixed_latitude``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    position_broadcast_secs: int | None = Field(default=None, ge=0)
    position_broadcast_smart_enabled: bool | None = None
    fixed_position: bool = False
    gps_update_interval: int | None = Field(default=None, ge=0)
    position_flags: int | None = Field(default=None, ge=0)
    broadcast_smart_minimum_distance: int | None = Field(default=None, ge=0)
    broadcast_smart_minimum_interval_secs: int | None = Field(default=None, ge=0)
    gps_mode: str | None = None
    fixed_latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    fixed_longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    fixed_altitude: int | None = None


class PowerSection(BaseModel):
    """``config.power`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.PowerConfig`` message.

    Attributes:
        is_power_saving: Whether the device sleeps aggressively between
            radio activity.
        on_battery_shutdown_after_secs: Seconds on battery power before
            automatic shutdown.
        adc_multiplier_override: Battery-voltage ADC multiplier override.
        wait_bluetooth_secs: Seconds to keep Bluetooth active after boot.
        sds_secs: Super-deep-sleep duration, seconds.
        ls_secs: Light-sleep duration, seconds.
        min_wake_secs: Minimum time to stay awake after a wake event,
            seconds.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_power_saving: bool | None = None
    on_battery_shutdown_after_secs: int | None = Field(default=None, ge=0)
    adc_multiplier_override: float | None = None
    wait_bluetooth_secs: int | None = Field(default=None, ge=0)
    sds_secs: int | None = Field(default=None, ge=0)
    ls_secs: int | None = Field(default=None, ge=0)
    min_wake_secs: int | None = Field(default=None, ge=0)


class TelemetrySection(BaseModel):
    """``ModuleConfig.telemetry`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.module_config_pb2.ModuleConfig.TelemetryConfig``
    message.

    Attributes:
        device_update_interval: Device-metrics telemetry interval,
            seconds.
        environment_measurement_enabled: Whether an environment sensor is
            read and reported.
        environment_update_interval: Environment telemetry interval,
            seconds.
        environment_screen_enabled: Whether environment readings appear
            on the device screen.
        environment_display_fahrenheit: Whether the screen shows
            temperature in Fahrenheit rather than Celsius.
        air_quality_enabled: Whether an air-quality sensor is read and
            reported.
        air_quality_interval: Air-quality telemetry interval, seconds.
        power_measurement_enabled: Whether a power/INA sensor is read and
            reported.
        power_update_interval: Power telemetry interval, seconds.
        power_screen_enabled: Whether power readings appear on the device
            screen.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_update_interval: int | None = Field(default=None, ge=0)
    environment_measurement_enabled: bool | None = None
    environment_update_interval: int | None = Field(default=None, ge=0)
    environment_screen_enabled: bool | None = None
    environment_display_fahrenheit: bool | None = None
    air_quality_enabled: bool | None = None
    air_quality_interval: int | None = Field(default=None, ge=0)
    power_measurement_enabled: bool | None = None
    power_update_interval: int | None = Field(default=None, ge=0)
    power_screen_enabled: bool | None = None


class SecuritySection(BaseModel):
    """``config.security`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.SecurityConfig`` message.
    Deliberately excludes ``private_key``/``public_key``/``admin_key``:
    key material never appears in a template file (enforced by
    :meth:`_reject_key_material`). Also omits a ``bluetooth_logging_enabled``
    field some secondary documentation mentions -- no such field exists
    in the installed protobuf, so it was dropped rather than guessed.

    Attributes:
        is_managed: Whether this node is locked into admin-managed mode.
            Requires 1-3 ``admin_nodes`` (enforced below) and, at
            provisioning time, an explicit ``--allow-lockdown`` plus a
            clean weak-key audit.
        admin_channel_enabled: Whether the legacy admin channel is
            active. Must stay ``False`` -- meshprovision never uses it.
        serial_enabled: Whether the serial console/API is enabled.
        debug_log_api_enabled: Whether verbose debug logging is exposed
            over the API.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_managed: bool = False
    admin_channel_enabled: bool = False
    serial_enabled: bool | None = None
    debug_log_api_enabled: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def _reject_key_material(cls, data: object) -> object:
        """Refuse a template that embeds raw key material.

        Args:
            data: The raw input to this section, before field validation.

        Returns:
            ``data`` unchanged, when it contains no key-material keys.

        Raises:
            TemplateValidationError: If ``data`` is a mapping containing
                ``private_key``, ``public_key``, ``admin_key``, or
                ``adminKey``.
        """
        if isinstance(data, Mapping):
            for key in _KEY_MATERIAL_KEYS:
                if key in data:
                    raise TemplateValidationError(
                        "Key material must never appear in the template.",
                        field=f"security.{key}",
                        hint=(
                            "Admin keys are derived from `admin_nodes` and resolved "
                            "from the Keys sheet; per-node keys are generated by "
                            "`mesh provision`."
                        ),
                    )
        return data


class TemplateConfig(BaseModel):
    """The full provisioning template.

    Immutable once validated (``frozen=True``): :meth:`_check_consistency`
    runs once, at construction, and only ever validates -- it never
    mutates ``self``.

    Attributes:
        version: Template schema version.
        enabled_options: Module options to enable. An option may not
            appear in both this and :attr:`disabled_options`.
        disabled_options: Module options to disable.
        short_name_pattern: ``{n}``-placeholder pattern for the node's
            ``short_name``. Widest rendering must fit
            :data:`SHORT_NAME_MAX_BYTES`.
        long_name_pattern: ``{n}``-placeholder pattern for the node's
            ``long_name``. Widest rendering must fit
            :data:`LONG_NAME_MAX_BYTES`.
        name_suffix_alphabet: Alphabet each ``{n}`` slot draws from.
        name_min_capacity: Namespace-capacity floor for
            :attr:`short_name_pattern`; crossing it below is a warning,
            or (with :attr:`name_capacity_strict`) a hard error.
        name_capacity_warn_utilization: Utilization ratio at which
            :func:`check_capacity_utilization` warns.
        name_capacity_strict: Whether falling below
            :attr:`name_min_capacity` is a hard error rather than a
            warning.
        admin_nodes: 0-3 admin node references. Each must resolve to a
            ``<ref>_pub`` row in the Keys sheet at provisioning time --
            that resolution is deliberately not attempted here, since
            the database may not exist yet when a template is loaded.
        device: ``config.device`` fields.
        lora: ``config.lora`` fields.
        position: ``config.position`` fields.
        power: ``config.power`` fields.
        telemetry: ``ModuleConfig.telemetry`` fields.
        security: ``config.security`` fields.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )

    version: int = Field(default=1, ge=1)
    enabled_options: tuple[str, ...] = ()
    disabled_options: tuple[str, ...] = ()
    short_name_pattern: str = "MT{n}{n}"
    long_name_pattern: str = "Meshtastic MT{n}{n}"
    name_suffix_alphabet: str = BASE36_ALPHABET
    name_min_capacity: int = Field(default=DEFAULT_MIN_CAPACITY, ge=1)
    name_capacity_warn_utilization: float = Field(default=DEFAULT_WARN_UTILIZATION, gt=0.0, le=1.0)
    name_capacity_strict: bool = False
    admin_nodes: tuple[str, ...] = ()
    device: DeviceSection = Field(default_factory=DeviceSection)
    lora: LoraSection = Field(default_factory=LoraSection)
    position: PositionSection = Field(default_factory=PositionSection)
    power: PowerSection = Field(default_factory=PowerSection)
    telemetry: TelemetrySection = Field(default_factory=TelemetrySection)
    security: SecuritySection = Field(default_factory=SecuritySection)

    @field_validator("enabled_options", "disabled_options", "admin_nodes", mode="before")
    @classmethod
    def _coerce_str_tuple(cls, value: object) -> tuple[str, ...]:
        """Normalize a raw list into a de-duplicated tuple of strings.

        Args:
            value: The raw field value.

        Returns:
            The normalized tuple. See :func:`_normalize_str_tuple`.
        """
        return _normalize_str_tuple(value)

    @field_validator("enabled_options", "disabled_options", mode="after")
    @classmethod
    def _lowercase_options(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Lowercase every module option name.

        Args:
            value: The already-normalized tuple of option names.

        Returns:
            The same tuple, lowercased.
        """
        return tuple(v.lower() for v in value)

    @model_validator(mode="after")
    def _check_consistency(self) -> TemplateConfig:
        """Cross-field validation, run once after all fields validate.

        Checks, in order, raising on the first failure: no option in
        both enabled/disabled lists; both name patterns fit their
        firmware byte limits; the short-name capacity floor (only a hard
        error under ``name_capacity_strict``); ``admin_nodes`` count and
        reference format; the admin-channel interlock; the
        zero-admin-keys lockdown interlock; and that ``device.role``/
        ``lora.region`` are known enum names.

        Returns:
            ``self``, unchanged -- this method only validates.

        Raises:
            TemplateValidationError: For most of the checks above.
            NamePatternError: If a name pattern's widest rendering
                overflows its firmware byte limit.
            NameCapacityError: If the short-name capacity is below the
                configured floor and ``name_capacity_strict`` is true.
            AdminKeyCapacityError: If more than
                :data:`~meshprovision.errors.MAX_ADMIN_KEYS` admin node
                references are configured.
        """
        overlap = sorted(set(self.enabled_options) & set(self.disabled_options))
        if overlap:
            raise TemplateValidationError(
                f"Option(s) {', '.join(overlap)} appear in both enabled_options "
                "and disabled_options.",
                field="enabled_options",
            )

        short = PatternSpec.compile(
            self.short_name_pattern, self.name_suffix_alphabet, field="short_name_pattern"
        )
        if short.widest_byte_length() > SHORT_NAME_MAX_BYTES:
            rendered = short.render_widest()
            byte_length = len(rendered.encode("utf-8"))
            raise NamePatternError(
                f"short_name_pattern {self.short_name_pattern!r} renders at most "
                f"{rendered!r}, which is {byte_length} UTF-8 bytes; the firmware "
                "limit is 4 bytes and it truncates silently.",
                pattern=self.short_name_pattern,
                rendered=rendered,
                byte_length=byte_length,
                limit=SHORT_NAME_MAX_BYTES,
                field="short_name_pattern",
            )

        long_spec = PatternSpec.compile(
            self.long_name_pattern, self.name_suffix_alphabet, field="long_name_pattern"
        )
        if long_spec.widest_byte_length() > LONG_NAME_MAX_BYTES:
            rendered = long_spec.render_widest()
            byte_length = len(rendered.encode("utf-8"))
            raise NamePatternError(
                f"long_name_pattern {self.long_name_pattern!r} renders at most "
                f"{rendered!r}, which is {byte_length} UTF-8 bytes; the firmware "
                "limit is 39 bytes and it truncates silently.",
                pattern=self.long_name_pattern,
                rendered=rendered,
                byte_length=byte_length,
                limit=LONG_NAME_MAX_BYTES,
                field="long_name_pattern",
            )

        if short.capacity < self.name_min_capacity and self.name_capacity_strict:
            raise NameCapacityError(
                f"short_name_pattern {self.short_name_pattern!r} over a "
                f"{len(self.name_suffix_alphabet)}-character alphabet yields only "
                f"{short.capacity} names, below the configured floor of "
                f"{self.name_min_capacity}.",
                pattern=self.short_name_pattern,
                capacity=short.capacity,
                floor=self.name_min_capacity,
                field="short_name_pattern",
            )

        if len(self.admin_nodes) > MAX_ADMIN_KEYS:
            raise AdminKeyCapacityError(
                f"admin_nodes has {len(self.admin_nodes)} entries; the firmware "
                f"supports at most {MAX_ADMIN_KEYS}.",
                count=len(self.admin_nodes),
                limit=MAX_ADMIN_KEYS,
            )
        for ref in self.admin_nodes:
            if not _ADMIN_REF_PATTERN.match(ref):
                raise TemplateValidationError(
                    f"admin_nodes entry {ref!r} is not a valid node reference "
                    "(expected 1-64 characters from [A-Za-z0-9._-], starting with "
                    "an alphanumeric).",
                    field="admin_nodes",
                )
            if ref.endswith("_pub") or ref.endswith("_priv"):
                raise TemplateValidationError(
                    f"admin_nodes entry {ref!r} must not end in '_pub' or '_priv'.",
                    field="admin_nodes",
                    hint=(
                        "admin_nodes holds node references; meshprovision appends "
                        "_pub/_priv itself when it looks up the Keys sheet."
                    ),
                )

        if self.security.admin_channel_enabled:
            raise TemplateValidationError(
                "The legacy admin channel is never used by meshprovision; "
                "admin_channel_enabled must be false.",
                field="security.admin_channel_enabled",
            )

        if self.security.is_managed and not self.admin_nodes:
            raise TemplateValidationError(
                "is_managed=true with zero admin_nodes would lock the node with "
                "nobody able to administer it.",
                field="security.is_managed",
                hint="Add 1-3 refs to admin_nodes, or set security.is_managed to false.",
            )

        if not role_table().contains_name(self.device.role):
            known = ", ".join(role_table().names()[:8])
            raise TemplateValidationError(
                f"device.role {self.device.role!r} is not a known role. Known "
                f"roles include: {known}.",
                field="device.role",
            )
        if not region_table().contains_name(self.lora.region):
            known = ", ".join(region_table().names()[:8])
            raise TemplateValidationError(
                f"lora.region {self.lora.region!r} is not a known region. Known "
                f"regions include: {known}.",
                field="lora.region",
            )

        return self

    def short_name_spec(self) -> PatternSpec:
        """Compile :attr:`short_name_pattern`.

        Returns:
            The compiled :class:`PatternSpec`.
        """
        return PatternSpec.compile(
            self.short_name_pattern, self.name_suffix_alphabet, field="short_name_pattern"
        )

    def long_name_spec(self) -> PatternSpec:
        """Compile :attr:`long_name_pattern`.

        Returns:
            The compiled :class:`PatternSpec`.
        """
        return PatternSpec.compile(
            self.long_name_pattern, self.name_suffix_alphabet, field="long_name_pattern"
        )

    def option_state(self) -> Mapping[str, bool]:
        """Build a single enabled/disabled mapping over every configured option.

        Returns:
            A read-only mapping: ``True`` for each name in
            :attr:`enabled_options`, ``False`` for each name in
            :attr:`disabled_options`.
        """
        state: dict[str, bool] = {}
        for opt in self.enabled_options:
            state[opt] = True
        for opt in self.disabled_options:
            state[opt] = False
        return MappingProxyType(state)

    def admin_key_refs(self) -> tuple[str, ...]:
        """Build the Keys-sheet public-key references for every admin node.

        Returns:
            ``tuple(admin_public_key_ref(r) for r in admin_nodes)``.
        """
        return tuple(admin_public_key_ref(ref) for ref in self.admin_nodes)

    def collect_warnings(self) -> tuple[TemplateWarning, ...]:
        """Compute every non-fatal finding about this template.

        Pure and deterministic. Does not need any database state, unlike
        :func:`check_capacity_utilization` (which needs the count of
        names already in use, not knowable at template-load time).

        Returns:
            A tuple of :class:`TemplateWarning`, in a fixed order:
            unknown module options first, then a capacity-below-floor
            warning (when not already a hard error), then a
            long-name-near-limit warning.
        """
        warnings: list[TemplateWarning] = []
        for opt in self.enabled_options:
            if opt not in KNOWN_MODULE_OPTIONS:
                warnings.append(
                    TemplateWarning(
                        "unknown_option",
                        f"Option {opt!r} is not a known Meshtastic module option; "
                        "it will be passed through unchanged.",
                        field="enabled_options",
                    )
                )
        for opt in self.disabled_options:
            if opt not in KNOWN_MODULE_OPTIONS:
                warnings.append(
                    TemplateWarning(
                        "unknown_option",
                        f"Option {opt!r} is not a known Meshtastic module option; "
                        "it will be passed through unchanged.",
                        field="disabled_options",
                    )
                )

        short = self.short_name_spec()
        if short.capacity < self.name_min_capacity:
            warnings.append(
                TemplateWarning(
                    "capacity_below_floor",
                    f"short_name_pattern {self.short_name_pattern!r} over a "
                    f"{len(self.name_suffix_alphabet)}-character alphabet yields "
                    f"only {short.capacity} names (configured floor "
                    f"{self.name_min_capacity}).",
                    field="short_name_pattern",
                )
            )

        long_spec = self.long_name_spec()
        if long_spec.widest_byte_length() > LONG_NAME_MAX_BYTES - 4:
            warnings.append(
                TemplateWarning(
                    "long_name_near_limit",
                    f"long_name_pattern {self.long_name_pattern!r} renders at "
                    f"{long_spec.widest_byte_length()} UTF-8 bytes, within 4 bytes "
                    "of the 39-byte firmware limit.",
                    field="long_name_pattern",
                )
            )

        return tuple(warnings)


def load_template(path: Path | str) -> TemplateConfig:
    """Read, parse, and validate a template YAML file.

    Args:
        path: Path to the template file.

    Returns:
        The validated :class:`TemplateConfig`.

    Raises:
        TemplateValidationError: If the file does not exist, is not
            UTF-8, is not valid YAML, its top level is not a mapping, or
            its contents fail :class:`TemplateConfig` validation.
        MeshprovisionError: Any structured error a
            :class:`TemplateConfig` validator raised directly (for
            example :class:`~meshprovision.errors.NamePatternError`)
            propagates unchanged -- see the module docstring for why.
    """
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise TemplateValidationError(
            f"Template file not found: {resolved}",
            field=None,
            hint=(
                "Copy config/template.example.yaml to config/template.yaml and "
                "edit it, or set MESHPROVISION_TEMPLATE_PATH."
            ),
        )
    try:
        text = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise TemplateValidationError(f"{resolved} must be UTF-8 encoded.", field=None) from exc
    except OSError as exc:
        raise TemplateValidationError(
            f"Could not read template file {resolved}: {exc}", field=None
        ) from exc
    return load_template_text(text, source=str(resolved))


def load_template_text(text: str, *, source: str = "<string>") -> TemplateConfig:
    """Parse and validate template YAML already read into memory.

    Args:
        text: The template's raw YAML text.
        source: Human-readable description of where ``text`` came from,
            used in error messages and log lines.

    Returns:
        The validated :class:`TemplateConfig`.

    Raises:
        TemplateValidationError: If ``text`` is not valid YAML, its top
            level is not a mapping, or its contents fail
            :class:`TemplateConfig` validation.
        MeshprovisionError: Any structured error a :class:`TemplateConfig`
            validator raised directly propagates unchanged -- see the
            module docstring for why this loader deliberately does not
            catch it.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise TemplateValidationError(f"{source} is not valid YAML: {exc}", field=None) from exc

    if data is None:
        data = {}
    if not isinstance(data, Mapping):
        raise TemplateValidationError(f"The top level of {source} must be a mapping.", field=None)

    try:
        cfg = TemplateConfig.model_validate(data)
    except ValidationError as exc:
        raise TemplateValidationError(format_validation_error(exc, source=source)) from exc

    for warning in cfg.collect_warnings():
        _logger.warning("%s", warning.message)

    return cfg
