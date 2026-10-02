"""Per-section models of the provisioning template.

One pydantic model per ``config``/``module_config`` section a template may
set (``device``, ``lora``, ``position``, ``power``, ``telemetry``,
``neighbor_info``, ``default_channel``, ``security``), plus the shared
enum-canonicalizing helper their validators use. Split out of
:mod:`meshprovision.config.template` for size; that module imports and
re-exports every model here, so callers keep importing them from there.
:class:`~meshprovision.config.template.TemplateConfig` composes them and
owns every cross-section consistency check.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from meshprovision.enums import (
    EnumTable,
    gps_mode_table,
    modem_preset_table,
    packet_signature_policy_table,
    rebroadcast_mode_table,
    region_table,
    role_table,
)
from meshprovision.errors import EnumMappingError, TemplateValidationError

__all__ = [
    "DefaultChannelSection",
    "DeviceSection",
    "LoraSection",
    "NeighborInfoSection",
    "PositionSection",
    "PowerSection",
    "SecuritySection",
    "TelemetrySection",
]

_KEY_MATERIAL_KEYS: Final[frozenset[str]] = frozenset(
    {"private_key", "public_key", "admin_key", "adminKey"}
)

_POSITION_FIXED_KEYS: Final[frozenset[str]] = frozenset(
    {"fixed_latitude", "fixed_longitude", "fixed_altitude"}
)


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
        packet_signature_policy: Firmware 2.8's XEdDSA packet-signing
            policy name, validated and canonicalized against
            :func:`meshprovision.enums.packet_signature_policy_table`.
            ``None`` means leave the device's current value untouched.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_managed: bool = False
    admin_channel_enabled: bool = False
    serial_enabled: bool | None = None
    debug_log_api_enabled: bool | None = None
    packet_signature_policy: str | None = None

    @field_validator("packet_signature_policy", mode="before")
    @classmethod
    def _canonicalize_packet_signature_policy(cls, value: object) -> object:
        """Canonicalize ``packet_signature_policy`` against its enum table.

        Args:
            value: The raw field value.

        Returns:
            ``None``, or the canonical protobuf enum name.
        """
        return _canonicalize_enum_field(
            value,
            table=packet_signature_policy_table(),
            field="security.packet_signature_policy",
        )

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
