"""Template field bounds agree with the min/max the protobufs annotate."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from typing import Any

import annotated_types
import pytest
from pydantic import BaseModel

from meshprovision.config import template_sections as ts
from meshprovision.config.template import TemplateConfig

pytestmark = pytest.mark.unit

# (template section, its model, dotted path of the protobuf message in the library).
_SECTIONS: tuple[tuple[str, type[BaseModel], tuple[str, str]], ...] = (
    ("device", ts.DeviceSection, ("config_pb2", "Config.DeviceConfig")),
    ("lora", ts.LoraSection, ("config_pb2", "Config.LoRaConfig")),
    ("position", ts.PositionSection, ("config_pb2", "Config.PositionConfig")),
    ("power", ts.PowerSection, ("config_pb2", "Config.PowerConfig")),
    ("security", ts.SecuritySection, ("config_pb2", "Config.SecurityConfig")),
    ("telemetry", ts.TelemetrySection, ("module_config_pb2", "ModuleConfig.TelemetryConfig")),
    (
        "neighbor_info",
        ts.NeighborInfoSection,
        ("module_config_pb2", "ModuleConfig.NeighborInfoConfig"),
    ),
    ("default_channel", ts.DefaultChannelSection, ("channel_pb2", "ModuleSettings")),
)


def _message_class(module_name: str, dotted: str) -> Any:
    module = pytest.importorskip(f"meshtastic.protobuf.{module_name}")
    message: Any = module
    for part in dotted.split("."):
        message = getattr(message, part)
    return message


def _model_bound(model: type[BaseModel], name: str, kind: type[Any], attr: str) -> float | None:
    for constraint in model.model_fields[name].metadata:
        if isinstance(constraint, kind):
            bound: float = getattr(constraint, attr)
            return bound
    return None


def _bounded_template_fields() -> Iterator[tuple[str, list[str]]]:
    """Yield ``section.field`` for each template field the protobufs bound.

    The second item lists where the template's bounds differ from the
    annotated ones (empty when they agree).
    """
    field_metadata_pb2 = pytest.importorskip("meshtastic.protobuf.field_metadata_pb2")
    extension = field_metadata_pb2.field_metadata
    for section, model, (module_name, dotted) in _SECTIONS:
        for descriptor in _message_class(module_name, dotted).DESCRIPTOR.fields:
            options = descriptor.GetOptions()
            if descriptor.name not in model.model_fields or not options.HasExtension(extension):
                continue
            metadata = options.Extensions[extension]
            # HasField: a minimum of 0 is a bound too, but falsy.
            bounds = [
                (kind, ours, attr)
                for kind, ours, attr in (
                    (annotated_types.Ge, "ge", "min_value"),
                    (annotated_types.Le, "le", "max_value"),
                )
                if metadata.HasField(attr)
            ]
            if not bounds:
                continue
            yield (
                f"{section}.{descriptor.name}",
                [
                    f"{ours}: protobuf {getattr(metadata, attr)}, "
                    f"template {_model_bound(model, descriptor.name, kind, ours)}"
                    for kind, ours, attr in bounds
                    if _model_bound(model, descriptor.name, kind, ours) != getattr(metadata, attr)
                ],
            )


def test_template_bounds_match_protobuf_field_metadata() -> None:
    mismatches = {name: found for name, found in _bounded_template_fields() if found}

    assert not mismatches, f"template bounds differ from the protobufs: {mismatches}"


def test_field_metadata_bounds_reach_at_least_one_template_field() -> None:
    # The pin guarantees the module, so a missing one fails here instead of skipping.
    importlib.import_module("meshtastic.protobuf.field_metadata_pb2")
    template_sections = {
        name
        for name, field in TemplateConfig.model_fields.items()
        if isinstance(field.annotation, type) and issubclass(field.annotation, BaseModel)
    }
    checked = {name for name, _ in _bounded_template_fields()}

    assert {name for name, _, _ in _SECTIONS} == template_sections
    assert "lora.hop_limit" in checked
