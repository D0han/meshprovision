"""Unit-only fixtures and builders, private to the ``tests/unit`` group.

Everything here is layered on top of the shared fixtures/constants
``tests/conftest.py`` (owned by this same group but shared with the e2e
group) already provides. The centerpiece is :func:`live_config_from_template`,
which is the single builder every plan/detect/apply unit test uses to
build a :class:`~meshprovision.provisioning.detect.LiveConfig` that is
*already correct* against a given template -- so a test asserting an
empty diff can trust that any observed change is a genuine bug, not an
artifact of a hand-built fixture drifting from the template.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType

import pytest
from odf import opendocument
from odf import table as odf_table
from odf import text as odf_text

from meshprovision.config.template import TemplateConfig
from meshprovision.crypto import redact
from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.db import schema
from meshprovision.provisioning import detect
from meshprovision.provisioning.detect import LiveConfig, LiveSecurity
from meshprovision.provisioning.plan import ResolvedAdminKey

pytestmark = pytest.mark.unit

_POSITION_FIXED_FIELDS = frozenset({"fixed_latitude", "fixed_longitude", "fixed_altitude"})


def live_config_from_template(
    template: TemplateConfig,
    *,
    node_id: str = "deadbe01",
    short_name: str = "MT00",
    long_name: str = "Meshtastic MT00",
    hw_model: str = "RAK4631",
    firmware_version: str = "2.7.11",
    security: LiveSecurity | None = None,
    section_overrides: Mapping[str, Mapping[str, object]] | None = None,
    module_enabled_overrides: Mapping[str, bool | None] | None = None,
) -> LiveConfig:
    """Build a :class:`LiveConfig` that is already correct against ``template``.

    Args:
        template: The template this live config should already satisfy.
        node_id: The device's node id, in any form
            :meth:`~meshprovision.nodeid.NodeId.from_hex` accepts.
        short_name: The device's current ``short_name``.
        long_name: The device's current ``long_name``.
        hw_model: The device's reported hardware model.
        firmware_version: The device's reported firmware version.
        security: The live security section. Defaults to an empty
            :class:`LiveSecurity` when not given.
        section_overrides: Per-section field overrides, applied last, one
            section at a time (a plain ``dict.update``, not a deep merge).
        module_enabled_overrides: ``module_enabled`` overrides, applied
            last directly onto the computed mapping.

    Returns:
        The constructed, immutable :class:`LiveConfig`.
    """
    from meshprovision.nodeid import NodeId

    sections: dict[str, dict[str, object]] = {}
    for name in ("device", "position", "power", "lora"):
        model = getattr(template, name)
        dumped = dict(model.model_dump(exclude_none=True))
        if name == "position":
            for field_name in _POSITION_FIXED_FIELDS:
                dumped.pop(field_name, None)
        sections[name] = dumped

    module_sections: dict[str, dict[str, object]] = {
        "telemetry": dict(template.telemetry.model_dump(exclude_none=True))
    }

    module_enabled: dict[str, bool | None] = dict.fromkeys(detect.MODULE_SECTIONS)
    for opt, want in template.option_state().items():
        module_enabled[opt] = want
    module_enabled["telemetry"] = None

    if section_overrides:
        for name, overrides in section_overrides.items():
            sections.setdefault(name, {}).update(overrides)

    if module_enabled_overrides:
        module_enabled.update(module_enabled_overrides)

    frozen_sections = MappingProxyType(
        {name: MappingProxyType(dict(values)) for name, values in sections.items()}
    )
    frozen_module_sections = MappingProxyType(
        {name: MappingProxyType(dict(values)) for name, values in module_sections.items()}
    )
    frozen_module_enabled = MappingProxyType(dict(module_enabled))

    return LiveConfig(
        node_id=NodeId.from_hex(node_id),
        short_name=short_name,
        long_name=long_name,
        hw_model=hw_model,
        firmware_version=firmware_version,
        security=security if security is not None else LiveSecurity(),
        sections=frozen_sections,
        module_sections=frozen_module_sections,
        module_enabled=frozen_module_enabled,
    )


@pytest.fixture
def make_live() -> Callable[..., LiveConfig]:
    """Expose :func:`live_config_from_template` as a fixture.

    Returns:
        The :func:`live_config_from_template` function.
    """
    return live_config_from_template


def make_security(
    *,
    keypair: KeyPair | None = None,
    admin_keys: tuple[bytes, ...] = (),
    is_managed: bool = False,
    admin_channel_enabled: bool = False,
    serial_enabled: bool | None = False,
    debug_log_api_enabled: bool | None = False,
    empty: bool = False,
) -> LiveSecurity:
    """Build a :class:`LiveSecurity` for tests.

    Args:
        keypair: When given, populates ``public_key``/``private_key``
            from it.
        admin_keys: The device's currently authorized admin public keys.
        is_managed: Whether the device is locked into admin-managed mode.
        admin_channel_enabled: Whether the legacy admin channel is active.
        serial_enabled: Whether the serial console/API is enabled.
        debug_log_api_enabled: Whether verbose debug logging is exposed.
        empty: When ``True``, ignore every other argument and return a
            completely empty (factory-default) :class:`LiveSecurity`.

    Returns:
        The constructed :class:`LiveSecurity`.
    """
    if empty:
        return LiveSecurity()
    return LiveSecurity(
        public_key=keypair.public if keypair is not None else None,
        private_key=keypair.private if keypair is not None else None,
        admin_keys=tuple(admin_keys),
        is_managed=is_managed,
        admin_channel_enabled=admin_channel_enabled,
        serial_enabled=serial_enabled,
        debug_log_api_enabled=debug_log_api_enabled,
    )


def _build_admin_key(
    ref: str = "ADMIN1",
    *,
    public: bytes | None = None,
    has_private: bool = True,
    audit_ok: bool = True,
    private_mismatch: bool = False,
    audit_summary: str = "",
) -> ResolvedAdminKey:
    """Build a :class:`ResolvedAdminKey` for tests.

    Args:
        ref: The ``admin_nodes`` entry this key belongs to.
        public: The raw 32-byte public key. Defaults to a freshly
            generated one, so distinct calls never collide.
        has_private: Whether the matching private key is on hand.
        audit_ok: Whether this key passed the weak-key audit.
        private_mismatch: Whether a private counterpart row exists but
            does not derive this public key.
        audit_summary: Human-readable summary of the audit result.

    Returns:
        The constructed :class:`ResolvedAdminKey`.
    """
    resolved_public = public if public is not None else generate_keypair().public
    return ResolvedAdminKey(
        ref=ref,
        key_ref=f"{ref}_pub",
        public=resolved_public,
        has_private=has_private,
        audit_ok=audit_ok,
        fingerprint=redact.fingerprint(resolved_public),
        audit_summary=audit_summary,
        private_mismatch=private_mismatch,
    )


@pytest.fixture
def make_admin_key() -> Callable[..., ResolvedAdminKey]:
    """Expose :func:`_build_admin_key` as a fixture.

    Returns:
        The :func:`_build_admin_key` function.
    """
    return _build_admin_key


def edit_ods_cell(
    path: Path,
    sheet: str,
    column: str,
    ods_row: int,
    new_text: str,
    *,
    value_type: str = "string",
) -> None:
    """Hand-edit one ODS cell, simulating an operator edit in LibreOffice.

    Args:
        path: Path to the ``.ods`` file to edit in place.
        sheet: The sheet name (``"Nodes"`` or ``"Keys"``).
        column: The schema column NAME to edit.
        ods_row: 1-based row number, with the header at row 1.
        new_text: The new cell text to write.
        value_type: The cell's ``table:value-type`` attribute. Defaults
            to ``"string"``; pass e.g. ``"float"`` to simulate
            LibreOffice coercing a text-kind column to a numeric type.
    """
    doc = opendocument.load(str(path))
    table_elem = None
    for candidate in doc.spreadsheet.getElementsByType(odf_table.Table):
        if candidate.getAttribute("name") == sheet:
            table_elem = candidate
            break
    if table_elem is None:
        raise AssertionError(f"No sheet named {sheet!r} found in {path}")

    rows = table_elem.getElementsByType(odf_table.TableRow)
    cells = rows[ods_row - 1].getElementsByType(odf_table.TableCell)
    column_index = schema.SHEET_SPECS[sheet].column_index(column)
    cell = cells[column_index]

    for child in list(cell.childNodes):
        cell.removeChild(child)
    cell.setAttribute("valuetype", value_type)
    if value_type == "string":
        cell.setAttribute("stringvalue", new_text)
    cell.addElement(odf_text.P(text=new_text))

    with path.open("wb") as fh:
        doc.write(fh)


@pytest.fixture
def factory_live(make_live: Callable[..., LiveConfig]) -> LiveConfig:
    """Build a :class:`LiveConfig` with factory-default names and no security.

    Args:
        make_live: The :func:`live_config_from_template` fixture.

    Returns:
        A :class:`LiveConfig` for node ``deadbe01`` with factory names
        (``"be01"`` / ``"Meshtastic be01"``) and an empty
        :class:`LiveSecurity`.
    """
    from meshprovision.config.template import load_template_text

    template = load_template_text("version: 1\n")
    return make_live(
        template,
        short_name="be01",
        long_name="Meshtastic be01",
        security=make_security(empty=True),
    )
