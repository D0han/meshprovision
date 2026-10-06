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
from meshtastic.protobuf import config_pb2, localonly_pb2, module_config_pb2

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
