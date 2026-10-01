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
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from meshprovision.config.settings import format_validation_error
from meshprovision.db.observed_keys import OBSERVED_PREFIX, RefProblem, owner_ref_problem
from meshprovision.enums import (
    EnumTable,
    gps_mode_table,
    modem_preset_table,
    rebroadcast_mode_table,
    region_table,
    role_table,
)
from meshprovision.errors import (
    MAX_ADMIN_KEYS,
    AdminKeyCapacityError,
    EnumMappingError,
    NameCapacityError,
    NamePatternError,
    TemplateValidationError,
)
from meshprovision.name_pattern import (
    BASE36_ALPHABET,
    DEFAULT_MIN_CAPACITY,
    DEFAULT_WARN_UTILIZATION,
    LONG_NAME_MAX_BYTES,
    SHORT_NAME_MAX_BYTES,
    PatternSpec,
    TemplateWarning,
)

__all__ = [
    "KNOWN_MODULE_OPTIONS",
    "DefaultChannelSection",
    "DeviceSection",
    "LoraSection",
    "NeighborInfoSection",
    "PositionSection",
    "PowerSection",
    "SecuritySection",
    "TelemetrySection",
    "TemplateConfig",
    "load_template",
    "load_template_text",
]

_logger = logging.getLogger(__name__)

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
:class:`TemplateWarning`. ``"neighbor_info"`` stays in this set (it is
still a real firmware module name) even though the list-toggle spelling
-- listing it in ``enabled_options``/``disabled_options`` -- is rejected
by :class:`TemplateConfig`'s consistency check in favor of the dedicated
``neighbor_info`` section."""

_KEY_MATERIAL_KEYS: Final[frozenset[str]] = frozenset(
    {"private_key", "public_key", "admin_key", "adminKey"}
)

_POSITION_FIXED_KEYS: Final[frozenset[str]] = frozenset(
    {"fixed_latitude", "fixed_longitude", "fixed_altitude"}
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


def _canonicalize_enum_field(value: object, *, table: EnumTable, field: str) -> object:
    """Canonicalize a template enum field against its protobuf table.

    Shared by the ``role``/``rebroadcast_mode``/``region``/``modem_preset``/
    ``gps_mode`` validators: ``None`` passes through unchanged (these
    fields are all optional except ``role``/``region``, which have string
    defaults and are never ``None``). Any other value is resolved to its
    canonical protobuf enum name via :meth:`EnumTable.to_name`, so a
    lowercase or typo'd value either becomes the exact stored form
    ``apply_field`` and ``values_equal`` expect, or is rejected here
    instead of surfacing mid-``mesh provision``.

    Args:
        value: The raw field value, before pydantic's own type coercion.
        table: The :class:`EnumTable` to validate ``value`` against.
        field: Dotted ``"<section>.<field>"`` name, for the error.

    Returns:
        ``None``, or the canonical protobuf enum name.

    Raises:
        TemplateValidationError: If ``value`` is not ``None`` and does not
            resolve to a known name in ``table``.
    """
    if value is None:
        return None
    if not isinstance(value, int | str):
        raise TemplateValidationError(
            f"{field} must be a string or integer, got {value!r}.",
            field=field,
        )
    try:
        return table.to_name(value)
    except EnumMappingError as exc:
        known = ", ".join(table.names()[:8])
        raise TemplateValidationError(
            f"{field} {value!r} is not a known {table.name}. Known values include: {known}.",
            field=field,
        ) from exc


class DeviceSection(BaseModel):
    """``config.device`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.DeviceConfig`` message.

    Attributes:
        role: Device role name, validated and canonicalized against
            :func:`meshprovision.enums.role_table`.
        rebroadcast_mode: Rebroadcast mode name, validated and
            canonicalized against
            :func:`meshprovision.enums.rebroadcast_mode_table`.
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

    @field_validator("role", mode="before")
    @classmethod
    def _canonicalize_role(cls, value: object) -> object:
        """Canonicalize ``role`` against :func:`~meshprovision.enums.role_table`.

        Args:
            value: The raw field value.

        Returns:
            The canonical protobuf enum name.
        """
        return _canonicalize_enum_field(value, table=role_table(), field="device.role")

    @field_validator("rebroadcast_mode", mode="before")
    @classmethod
    def _canonicalize_rebroadcast_mode(cls, value: object) -> object:
        """Canonicalize ``rebroadcast_mode`` against its enum table.

        Args:
            value: The raw field value.

        Returns:
            ``None``, or the canonical protobuf enum name.
        """
        return _canonicalize_enum_field(
            value, table=rebroadcast_mode_table(), field="device.rebroadcast_mode"
        )


class LoraSection(BaseModel):
    """``config.lora`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.LoRaConfig`` message.

    Attributes:
        region: LoRa region name, validated and canonicalized against
            :func:`meshprovision.enums.region_table`. Defaults to
            ``"EU_868"`` -- the Meshtastic ``RegionCode`` covering Poland;
            there is no ``"PL"`` region code in the protobuf.
        use_preset: Whether ``modem_preset`` governs the radio parameters
            (as opposed to manual bandwidth/spread-factor/coding-rate).
        modem_preset: Modem preset name, when ``use_preset`` is true.
            Validated and canonicalized against
            :func:`meshprovision.enums.modem_preset_table`.
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

    @field_validator("region", mode="before")
    @classmethod
    def _canonicalize_region(cls, value: object) -> object:
        """Canonicalize ``region`` against :func:`~meshprovision.enums.region_table`.

        Args:
            value: The raw field value.

        Returns:
            The canonical protobuf enum name.
        """
        return _canonicalize_enum_field(value, table=region_table(), field="lora.region")

    @field_validator("modem_preset", mode="before")
    @classmethod
    def _canonicalize_modem_preset(cls, value: object) -> object:
        """Canonicalize ``modem_preset`` against its enum table.

        Args:
            value: The raw field value.

        Returns:
            ``None``, or the canonical protobuf enum name.
        """
        return _canonicalize_enum_field(
            value, table=modem_preset_table(), field="lora.modem_preset"
        )


class PositionSection(BaseModel):
    """``config.position`` fields applied at provisioning time.

    Field names and types are drawn from the installed
    ``meshtastic.protobuf.config_pb2.Config.PositionConfig`` message.

    ``fixed_latitude``/``fixed_longitude``/``fixed_altitude`` are not
    accepted here: meshprovision never applies them (they are not
    ``PositionConfig`` fields, and would need the device's separate
    fixed-position API), so a template that sets any of the three is
    rejected outright rather than silently doing nothing. Set them with
    the ``meshtastic`` CLI's own ``--setlat``/``--setlon``/``--setalt``
    instead.

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
        gps_mode: GPS mode name (enabled/disabled/not-present), validated
            and canonicalized against
            :func:`meshprovision.enums.gps_mode_table`.
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

    @model_validator(mode="before")
    @classmethod
    def _reject_fixed_position_fields(cls, data: object) -> object:
        """Refuse a template that sets the unapplied fixed-position fields.

        Args:
            data: The raw input to this section, before field validation.

        Returns:
            ``data`` unchanged, when it contains none of the three keys.

        Raises:
            TemplateValidationError: If ``data`` is a mapping containing
                ``fixed_latitude``, ``fixed_longitude``, or
                ``fixed_altitude``.
        """
        if isinstance(data, Mapping):
            for key in _POSITION_FIXED_KEYS:
                if key in data:
                    raise TemplateValidationError(
                        f"position.{key} is not applied by meshprovision.",
                        field="position.fixed_latitude",
                        hint=(
                            "not applied by meshprovision; set with `meshtastic "
                            "--setlat/--setlon/--setalt` and remove from the template"
                        ),
                    )
        return data

    @field_validator("gps_mode", mode="before")
    @classmethod
    def _canonicalize_gps_mode(cls, value: object) -> object:
        """Canonicalize ``gps_mode`` against its enum table.

        Args:
            value: The raw field value.

        Returns:
            ``None``, or the canonical protobuf enum name.
        """
        return _canonicalize_enum_field(value, table=gps_mode_table(), field="position.gps_mode")


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
        device_telemetry_enabled: Whether device-metrics telemetry is
            collected at all.
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
        air_quality_screen_enabled: Whether air-quality readings appear
            on the device screen.
        power_measurement_enabled: Whether a power/INA sensor is read and
            reported.
        power_update_interval: Power telemetry interval, seconds.
        power_screen_enabled: Whether power readings appear on the device
            screen.
        health_measurement_enabled: Whether a health sensor is read and
            reported.
        health_update_interval: Health telemetry interval, seconds.
        health_screen_enabled: Whether health readings appear on the
            device screen.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_telemetry_enabled: bool | None = None
    device_update_interval: int | None = Field(default=None, ge=0)
    environment_measurement_enabled: bool | None = None
    environment_update_interval: int | None = Field(default=None, ge=0)
    environment_screen_enabled: bool | None = None
    environment_display_fahrenheit: bool | None = None
    air_quality_enabled: bool | None = None
    air_quality_interval: int | None = Field(default=None, ge=0)
    air_quality_screen_enabled: bool | None = None
    power_measurement_enabled: bool | None = None
    power_update_interval: int | None = Field(default=None, ge=0)
    power_screen_enabled: bool | None = None
    health_measurement_enabled: bool | None = None
    health_update_interval: int | None = Field(default=None, ge=0)
    health_screen_enabled: bool | None = None


class NeighborInfoSection(BaseModel):
    """``ModuleConfig.neighbor_info`` fields applied at provisioning time.

    Attributes:
        enabled: Whether the neighbor-info module is active. Supersedes
            listing ``"neighbor_info"`` in ``enabled_options``/
            ``disabled_options`` -- see ``TemplateConfig``'s consistency check.
        update_interval: Neighbor-info broadcast interval, seconds.
        transmit_over_lora: Whether neighbor info is transmitted over LoRa.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool | None = None
    update_interval: int | None = Field(default=None, ge=0)
    transmit_over_lora: bool | None = None


class DefaultChannelSection(BaseModel):
    """The primary (index-0) channel's ``ModuleSettings`` fields.

    Scoped to channel index 0 only -- meshprovision has no secondary-channel
    provisioning story. Deliberately not part of config/module-config: a
    device's channels live in a separate protobuf container
    (``iface.localNode.channels``), written through a different admin
    message (``AdminMessage.set_channel`` via ``Node.writeChannel``), never
    ``writeConfig``.

    Attributes:
        position_precision: Position precision shared in this channel's
            broadcasts, in bits (0 disables position sharing on this
            channel).
        is_muted: Whether this channel's traffic is muted (received but not
            relayed/notified).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    position_precision: int | None = Field(default=None, ge=0)
    is_muted: bool | None = None


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
        neighbor_info: ``ModuleConfig.neighbor_info`` fields.
        default_channel: The primary (index-0) channel's ``ModuleSettings``
            fields.
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
    neighbor_info: NeighborInfoSection = Field(default_factory=NeighborInfoSection)
    default_channel: DefaultChannelSection = Field(default_factory=DefaultChannelSection)
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
        both enabled/disabled lists; ``neighbor_info`` not in either
        list (use ``neighbor_info.enabled`` instead); both name patterns
        fit their firmware byte limits; the short-name capacity floor
        (only a hard error under ``name_capacity_strict``);
        ``admin_nodes`` count and reference format; the admin-channel
        interlock; and the zero-admin-keys lockdown interlock. Enum-typed fields
        (``device.role``, ``device.rebroadcast_mode``, ``lora.region``,
        ``lora.modem_preset``, ``position.gps_mode``) are validated and
        canonicalized earlier, per-field, rather than here.

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

        if "neighbor_info" in self.enabled_options or "neighbor_info" in self.disabled_options:
            bad_field = (
                "enabled_options" if "neighbor_info" in self.enabled_options else "disabled_options"
            )
            raise TemplateValidationError(
                "neighbor_info must not appear in enabled_options/disabled_options; "
                "set neighbor_info.enabled instead.",
                field=bad_field,
                hint=(
                    "Replace `neighbor_info` in the list with a "
                    "`neighbor_info: {enabled: true}` block."
                ),
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
                f"limit is {LONG_NAME_MAX_BYTES} bytes and it truncates silently.",
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
            problem = owner_ref_problem(ref)
            if problem is RefProblem.BAD_SHAPE:
                raise TemplateValidationError(
                    f"admin_nodes entry {ref!r} is not a valid node reference "
                    "(expected 1-64 characters from [A-Za-z0-9._-], starting with "
                    "an alphanumeric).",
                    field="admin_nodes",
                )
            if problem is RefProblem.RESERVED_SUFFIX:
                raise TemplateValidationError(
                    f"admin_nodes entry {ref!r} must not end in '_pub', '_priv', or '_psk'.",
                    field="admin_nodes",
                    hint=(
                        "admin_nodes holds node references; meshprovision appends "
                        "these suffixes itself when it looks up the Keys sheet."
                    ),
                )
            if problem is RefProblem.OBSERVED_PREFIX:
                raise TemplateValidationError(
                    f"admin_nodes entry {ref!r} must not start with {OBSERVED_PREFIX!r}.",
                    field="admin_nodes",
                    hint=(
                        "Give the key a real name with `mesh admin import --ref <NAME>` "
                        "(or `mesh admin bootstrap --ref <NAME>`) and list that name here."
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
            ``tuple(f"{r}_pub" for r in admin_nodes)`` -- equivalent to
            ``schema.ref_for(r, KeyType.ADMIN_PUBLIC)``, inlined rather than
            imported so this module keeps no dependency on :mod:`meshprovision.db`.
        """
        return tuple(f"{ref}_pub" for ref in self.admin_nodes)

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
                    f"of the {LONG_NAME_MAX_BYTES}-byte firmware limit.",
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
                "Run `mesh init`, copy config/template.example.yaml to "
                "config/template.yaml and edit it, or set MESHPROVISION_TEMPLATE_PATH."
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
        TemplateValidationError: If ``text`` is empty or comments-only
            (a YAML document that parses to ``None``), is not valid
            YAML, its top level is not a mapping, or its contents fail
            :class:`TemplateConfig` validation. An empty document is
            rejected rather than silently treated as ``{}``, since that
            would apply every field default (region, preset, role, name
            pattern) with no warning.
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
        raise TemplateValidationError(
            f"{source} is empty (no settings found)",
            field=None,
            hint=(
                "An empty template would silently apply built-in defaults (region, "
                "preset, role, name pattern) to every node. Restore your template, or "
                "run `mesh init` in a new directory for a starter file based on "
                "template.example.yaml."
            ),
        )
    if not isinstance(data, Mapping):
        raise TemplateValidationError(f"The top level of {source} must be a mapping.", field=None)

    try:
        cfg = TemplateConfig.model_validate(data)
    except ValidationError as exc:
        raise TemplateValidationError(format_validation_error(exc, source=source)) from exc

    for warning in cfg.collect_warnings():
        _logger.warning("%s", warning.message)

    return cfg
