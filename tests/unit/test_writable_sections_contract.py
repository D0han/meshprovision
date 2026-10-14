"""Contract: detect's writable section lists match the pinned library's ``Node.writeConfig``.

``Node.writeConfig`` is a hard-coded ``if``/``elif`` on the section name that
exits the process (``our_exit``: a line on stdout, then ``SystemExit(1)``)
for any name it does not know. A name in
:data:`~meshprovision.provisioning.detect.CONFIG_SECTIONS`/
:data:`~meshprovision.provisioning.detect.MODULE_SECTIONS` that the library
rejects would let a template plan a write that kills the run mid-transaction
(and corrupts ``--json`` stdout); a name the library accepts but the lists
lack would be refused by the template for no reason. Either drift is what a
bump of the pinned meshtastic commit could bring.

The candidates are every field name of the protobuf messages a section
could come from -- ``LocalConfig``/``LocalModuleConfig`` and the
``payload_variant`` oneofs of ``Config``/``ModuleConfig`` -- never the
lists under test. The descriptors name more sections than ``writeConfig``
accepts (``version``, ``sessionkey``, ``device_ui``, ``statusmessage``,
``tak``, ``mesh_beacon`` today), so they cannot be the expected set either.
"""

from __future__ import annotations

from typing import Final

import pytest
from google.protobuf.descriptor import Descriptor, FieldDescriptor
from meshtastic.protobuf import channel_pb2, config_pb2, localonly_pb2, module_config_pb2
from pydantic import BaseModel

from meshprovision.config.template import TemplateConfig
from meshprovision.enums import MODULES_WITHOUT_ENABLED, section_field_bounds
from meshprovision.provisioning import detect
from tests.conftest import real_write_config_or_exit

pytestmark = pytest.mark.unit


def _candidate_sections() -> tuple[str, ...]:
    names = {field.name for field in localonly_pb2.LocalConfig.DESCRIPTOR.fields}
    names |= {field.name for field in localonly_pb2.LocalModuleConfig.DESCRIPTOR.fields}
    for message in (config_pb2.Config, module_config_pb2.ModuleConfig):
        oneof = message.DESCRIPTOR.oneofs_by_name["payload_variant"]
        names |= {field.name for field in oneof.fields}
    return tuple(sorted(names))


_CANDIDATE_SECTIONS: Final[tuple[str, ...]] = _candidate_sections()


def _real_write_config_accepts(section: str) -> bool:
    try:
        real_write_config_or_exit(section)
    except SystemExit:
        return False
    return True


@pytest.mark.parametrize("section", _CANDIDATE_SECTIONS)
def test_writable_sections_match_what_the_real_write_config_accepts(section: str) -> None:
    listed = section in detect.CONFIG_SECTIONS or section in detect.MODULE_SECTIONS

    assert listed == _real_write_config_accepts(section)


def test_config_sections_are_local_config_fields() -> None:
    fields = {field.name for field in localonly_pb2.LocalConfig.DESCRIPTOR.fields}

    assert set(detect.CONFIG_SECTIONS) <= fields


def test_module_sections_are_local_module_config_fields() -> None:
    fields = {field.name for field in localonly_pb2.LocalModuleConfig.DESCRIPTOR.fields}

    assert set(detect.MODULE_SECTIONS) <= fields


def test_modules_without_enabled_are_exactly_those_lacking_the_field() -> None:
    by_name = localonly_pb2.LocalModuleConfig.DESCRIPTOR.fields_by_name
    lacking = {
        name
        for name in detect.MODULE_SECTIONS
        if "enabled" not in by_name[name].message_type.fields_by_name
    }

    assert set(MODULES_WITHOUT_ENABLED) == lacking
    assert "telemetry" in lacking


_TEMPLATE_SECTIONS: Final[tuple[str, ...]] = tuple(
    name
    for name, info in TemplateConfig.model_fields.items()
    if isinstance(info.annotation, type) and issubclass(info.annotation, BaseModel)
)

_NUMERIC_TYPES: Final[frozenset[int]] = frozenset(
    {
        FieldDescriptor.TYPE_INT32,
        FieldDescriptor.TYPE_SINT32,
        FieldDescriptor.TYPE_SFIXED32,
        FieldDescriptor.TYPE_UINT32,
        FieldDescriptor.TYPE_FIXED32,
        FieldDescriptor.TYPE_INT64,
        FieldDescriptor.TYPE_SINT64,
        FieldDescriptor.TYPE_SFIXED64,
        FieldDescriptor.TYPE_UINT64,
        FieldDescriptor.TYPE_FIXED64,
        FieldDescriptor.TYPE_FLOAT,
        FieldDescriptor.TYPE_DOUBLE,
    }
)


def _written_message(section: str) -> Descriptor:
    """The message ``provisioning/device_write.py`` writes ``section``'s fields into."""
    if section == "default_channel":
        return channel_pb2.ModuleSettings.DESCRIPTOR
    for parent in (localonly_pb2.LocalConfig, localonly_pb2.LocalModuleConfig):
        field = parent.DESCRIPTOR.fields_by_name.get(section)
        if field is not None:
            message: Descriptor = field.message_type
            return message
    raise AssertionError(f"no protobuf message for template section {section!r}")


def test_template_sections_are_the_expected_set() -> None:
    assert set(_TEMPLATE_SECTIONS) == {
        "device",
        "lora",
        "position",
        "power",
        "telemetry",
        "neighbor_info",
        "default_channel",
        "security",
    }


@pytest.mark.parametrize("section", _TEMPLATE_SECTIONS)
def test_every_template_section_field_is_a_field_of_its_protobuf_message(section: str) -> None:
    model = TemplateConfig.model_fields[section].annotation
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)

    assert set(model.model_fields) <= set(_written_message(section).fields_by_name)


@pytest.mark.parametrize("section", _TEMPLATE_SECTIONS)
def test_section_field_bounds_cover_exactly_the_numeric_fields_of_its_message(
    section: str,
) -> None:
    """Bounds come from the message the section is really written into, for every number."""
    expected = {
        field.name for field in _written_message(section).fields if field.type in _NUMERIC_TYPES
    }

    assert set(section_field_bounds(section)) == expected


@pytest.mark.parametrize(
    ("section", "field", "bounds"),
    [
        ("device", "node_info_broadcast_secs", (0, 2**32 - 1)),
        ("lora", "tx_power", (-(2**31), 2**31 - 1)),
        ("lora", "frequency_offset", (-3.4028234663852886e38, 3.4028234663852886e38)),
        ("power", "powermon_enables", (0, 2**64 - 1)),
    ],
)
def test_section_field_bounds_follow_the_wire_type(
    section: str, field: str, bounds: tuple[float, float]
) -> None:
    assert section_field_bounds(section)[field] == bounds
