"""The provisioning template model.

Validates ``config/template.yaml`` (or any template YAML) into a
:class:`TemplateConfig`: module options, the ``{n}``-placeholder name
patterns used to generate ``short_name``/``long_name`` for new nodes,
0-3 admin node references, and the ``lora``/``position``/``power``/
``telemetry``/``device``/``security`` config sections applied at
provisioning time. The per-section models (``DeviceSection``,
``LoraSection``, ...) live in :mod:`meshprovision.config.template_sections`
and are re-exported here unchanged; :class:`TemplateConfig` composes them
and owns every cross-section consistency check.

The name-pattern machinery lives in
:class:`~meshprovision.name_pattern.PatternSpec`: it compiles a
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
from meshprovision.config.template_sections import (
    DefaultChannelSection,
    DeviceSection,
    LoraSection,
    NeighborInfoSection,
    PositionSection,
    PowerSection,
    SecuritySection,
    TelemetrySection,
)
from meshprovision.db.observed_keys import OBSERVED_PREFIX, RefProblem, owner_ref_problem
from meshprovision.errors import (
    MAX_ADMIN_KEYS,
    AdminKeyCapacityError,
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
        is_unmessagable: Owner-identity field for nodes that should
            never receive direct messages (sensors/repeaters/
            infrastructure devices) -- written through the same admin
            message as :attr:`short_name_pattern`/:attr:`long_name_pattern`
            (``Node.setOwner``'s ``User.is_unmessagable``). ``None``
            (the default) leaves the device's current value untouched.
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
    is_unmessagable: bool | None = None
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
                        "Give the key a real name with `mesh admin import <NAME>=<BASE64>` "
                        "(`mesh adopt --show-admin-keys` prints that command with an observed "
                        "key's material filled in), or use `mesh admin bootstrap --ref <NAME>`, "
                        "and list that name here."
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
