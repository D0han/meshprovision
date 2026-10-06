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

import ast
import os
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from types import MappingProxyType

import pytest
from meshtastic.protobuf import channel_pb2
from odf import dc as odf_dc
from odf import office as odf_office
from odf import opendocument
from odf import table as odf_table
from odf import text as odf_text

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.crypto import redact
from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.db import schema
from meshprovision.db.keys import KeyRepository
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.provisioning import detect
from meshprovision.provisioning.detect import LiveConfig, LiveSecurity
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, build_plan
from meshprovision.provisioning.plan_admin_keys import ResolvedAdminKey

pytestmark = pytest.mark.unit


def live_config_from_template(
    template: TemplateConfig,
    *,
    node_id: str = "deadbe01",
    short_name: str = "MT00",
    long_name: str = "Meshtastic MT00",
    is_unmessagable: bool | None = None,
    is_licensed: bool = False,
    hw_model: str = "RAK4631",
    hw_model_raw: str | None = None,
    firmware_version: str = "2.7.11",
    security: LiveSecurity | None = None,
    section_overrides: Mapping[str, Mapping[str, object]] | None = None,
    module_enabled_overrides: Mapping[str, bool | None] | None = None,
    default_channel_overrides: Mapping[str, object] | None = None,
    primary_channel_enabled: bool = True,
) -> LiveConfig:
    """Build a :class:`LiveConfig` that is already correct against ``template``.

    Args:
        template: The template this live config should already satisfy.
        node_id: The device's node id, in any form
            :meth:`~meshprovision.nodeid.NodeId.from_hex` accepts.
        short_name: The device's current ``short_name``.
        long_name: The device's current ``long_name``.
        is_unmessagable: The device's current ``User.is_unmessagable``.
        is_licensed: The device's current ``User.is_licensed``.
        hw_model: The device's reported hardware model.
        hw_model_raw: The raw value ``hw_model`` was supposedly resolved
            from -- only meaningful (and normally only set) alongside
            ``hw_model=""``, to simulate an unrecognized live hw_model.
        firmware_version: The device's reported firmware version.
        security: The live security section. Defaults to an empty
            :class:`LiveSecurity` when not given.
        section_overrides: Per-section field overrides, applied last, one
            section at a time (a plain ``dict.update``, not a deep merge).
        module_enabled_overrides: ``module_enabled`` overrides, applied
            last directly onto the computed mapping.
        default_channel_overrides: ``default_channel`` overrides, applied
            last directly onto the computed mapping -- which models an
            enabled primary channel the way detect reads one: every
            ``ModuleSettings`` scalar at its default, overlaid with
            ``template.default_channel``'s own non-``None`` fields (so
            it already matches the template, and is never ``{}``).
        primary_channel_enabled: ``False`` models a device with no
            enabled primary channel (absent or ``DISABLED``): the live
            ``default_channel`` is then ``{}``, and
            ``default_channel_overrides`` is ignored.

    Returns:
        The constructed, immutable :class:`LiveConfig`.
    """
    from meshprovision.nodeid import NodeId

    sections: dict[str, dict[str, object]] = {}
    for name in ("device", "position", "power", "lora"):
        model = getattr(template, name)
        sections[name] = dict(model.model_dump(exclude_none=True))

    module_sections: dict[str, dict[str, object]] = {
        "telemetry": dict(template.telemetry.model_dump(exclude_none=True)),
        "neighbor_info": dict(template.neighbor_info.model_dump(exclude_none=True)),
    }

    module_enabled: dict[str, bool | None] = dict.fromkeys(detect.MODULE_SECTIONS)
    for opt, want in template.option_state().items():
        module_enabled[opt] = want
    module_enabled["telemetry"] = None
    module_enabled["neighbor_info"] = (
        template.neighbor_info.enabled if template.neighbor_info.enabled is not None else True
    )

    if section_overrides:
        for name, overrides in section_overrides.items():
            sections.setdefault(name, {}).update(overrides)

    if module_enabled_overrides:
        module_enabled.update(module_enabled_overrides)

    default_channel: dict[str, object] = {}
    if primary_channel_enabled:
        default_channel = {
            **detect._message_fields(channel_pb2.ModuleSettings()),
            **template.default_channel.model_dump(exclude_none=True),
            **(default_channel_overrides or {}),
        }

    frozen_sections = MappingProxyType(
        {name: MappingProxyType(dict(values)) for name, values in sections.items()}
    )
    frozen_module_sections = MappingProxyType(
        {name: MappingProxyType(dict(values)) for name, values in module_sections.items()}
    )
    frozen_module_enabled = MappingProxyType(dict(module_enabled))
    frozen_default_channel = MappingProxyType(dict(default_channel))

    return LiveConfig(
        node_id=NodeId.from_hex(node_id),
        short_name=short_name,
        long_name=long_name,
        is_unmessagable=is_unmessagable,
        is_licensed=is_licensed,
        hw_model=hw_model,
        hw_model_raw=hw_model_raw,
        firmware_version=firmware_version,
        security=security if security is not None else LiveSecurity(),
        sections=frozen_sections,
        module_sections=frozen_module_sections,
        module_enabled=frozen_module_enabled,
        default_channel=frozen_default_channel,
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
    packet_signature_policy: str | None = "PACKET_SIGNATURE_POLICY_COMPATIBLE",
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
        packet_signature_policy: The device's current XEdDSA
            packet-signing policy name.
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
        packet_signature_policy=packet_signature_policy,
    )


def _build_admin_key(
    ref: str = "ADMIN1",
    *,
    public: bytes | None = None,
    has_private: bool = True,
    audit_ok: bool = True,
    private_mismatch: bool = False,
    audit_summary: str = "",
    audit_overridable: bool = True,
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
        audit_overridable: Whether ``--allow-weak-admin-key`` could ever
            authorize this key despite a failed audit. Meaningless when
            ``audit_ok`` is ``True``.

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
        audit_overridable=audit_overridable,
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


def libreoffice_round_trip(path: Path) -> None:
    """Rewrite an ``.ods`` in place into the exact shape LibreOffice Calc saves.

    Simulates "open in Calc, resize a column, save" deterministically and
    without shelling out to ``soffice`` -- verified against a real
    ``soffice --headless --convert-to ods`` round trip of
    ``data/nodes_db.example.ods`` to produce the identical cell shape.
    LibreOffice's rewrite does two things this project's own writer never
    does:

    - Drops every plain (non-formula) cell's cached ``office:string-value``
      -- a formula cell keeps it, since LibreOffice still caches that
      cell's *computed* value.
    - On any cell carrying an ``office:annotation`` (a Calc comment --
      every header cell has one, holding its column description, see
      :func:`meshprovision.db.ods_write._build_header_row`), moves the
      annotation ahead of the cell's own ``text:p`` and adds a
      ``<dc:date>`` child to it.

    Args:
        path: Path to the ``.ods`` file to rewrite in place.
    """
    doc = opendocument.load(str(path))
    for table_elem in doc.spreadsheet.getElementsByType(odf_table.Table):
        for cell in table_elem.getElementsByType(odf_table.TableCell):
            if not cell.getAttribute("formula") and cell.getAttribute("stringvalue") is not None:
                cell.removeAttribute("stringvalue")
            annotation = next(
                (
                    child
                    for child in list(cell.childNodes)
                    if getattr(child, "qname", None) == (odf_office.OFFICENS, "annotation")
                ),
                None,
            )
            if annotation is None:
                continue
            cell.removeChild(annotation)
            annotation.insertBefore(odf_dc.Date(text="2026-01-01T00:00:00"), annotation.firstChild)
            cell.insertBefore(annotation, cell.firstChild)

    with path.open("wb") as fh:
        doc.write(fh)


def source_without_docstring(path: Path) -> str:
    """Return a module's code with its own docstring and comments stripped.

    A module guarded by one of the ``test_readonly_*_boundary.py`` tests
    *names* every forbidden token inside its own module docstring, so a
    naive text search matches the very rule it is checking. Round-tripping
    through :mod:`ast` removes the docstring and all comments, leaving only
    executable code.

    Args:
        path: The module to read.

    Returns:
        The module's source, re-rendered by :func:`ast.unparse` without its
        docstring.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
    ):
        del tree.body[0]
    return ast.unparse(tree)


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


def adopt_device_key_plan(
    make_live: Callable[..., LiveConfig], kp: KeyPair, other_kp: KeyPair
) -> ChangePlan:
    """Build a plan whose key_plan.adopt_device_key is True (db key differs from live)."""
    template = load_template_text("version: 1\n")
    live = make_live(template, security=make_security(keypair=kp))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        db_public_key=other_kp.public,
    )
    plan = build_plan(inputs)
    assert plan.key_plan.adopt_device_key is True
    assert plan.key_plan.regenerate is False
    return plan


FsyncEvent = tuple[str, int, bool]
"""One recorded durability step: ``(operation, inode, is_directory)``."""


@pytest.fixture
def fsync_recorder(monkeypatch: pytest.MonkeyPatch) -> list[FsyncEvent]:
    """Record every ``os.fsync``, ``os.replace`` and ``os.link``, in order.

    Replaces the root conftest's no-op ``os.fsync`` stub with a recorder
    (it still does not flush). Files are identified by inode, so a temp
    file and the final name it was renamed or linked to compare equal.
    ``Path.replace`` delegates to ``os.replace`` on every supported
    Python, so both are seen.

    Args:
        monkeypatch: Pytest's monkeypatch fixture.

    Returns:
        The event list, appended to as the test runs: ``("fsync", ino,
        is_dir)`` for a flush, ``("replace", ino, False)`` and ``("link",
        ino, False)`` for the source file of a rename or link.
    """
    events: list[FsyncEvent] = []
    real_replace, real_link = os.replace, os.link

    def record_fsync(fd: int) -> None:
        st = os.fstat(fd)
        events.append(("fsync", st.st_ino, stat.S_ISDIR(st.st_mode)))

    def record_replace(src: str | Path, dst: str | Path) -> None:
        events.append(("replace", Path(src).stat().st_ino, False))
        real_replace(src, dst)

    def record_link(src: str | Path, dst: str | Path) -> None:
        events.append(("link", Path(src).stat().st_ino, False))
        real_link(src, dst)

    monkeypatch.setattr(os, "fsync", record_fsync)
    monkeypatch.setattr(os, "replace", record_replace)
    monkeypatch.setattr(os, "link", record_link)
    return events


@pytest.fixture
def db(empty_ods: Path) -> OdsDatabase:
    """A loaded session over a fresh, empty database.

    Args:
        empty_ods: The root conftest's empty database file.

    Returns:
        The loaded session that :func:`nodes` and :func:`keys` share.
    """
    session = OdsDatabase(empty_ods)
    session.load()
    return session


@pytest.fixture
def nodes(db: OdsDatabase) -> NodeRepository:
    """The node repository over :func:`db`.

    It shares one session with :func:`keys`, as every command's database
    session does, so each sees the other's writes and a ``save()`` writes
    both sheets together.

    Args:
        db: The shared session.

    Returns:
        A :class:`~meshprovision.db.nodes.NodeRepository` over ``db``.
    """
    return NodeRepository(db)


@pytest.fixture
def keys(db: OdsDatabase) -> KeyRepository:
    """The key repository over :func:`db`, sharing its session with :func:`nodes`.

    Args:
        db: The shared session.

    Returns:
        A :class:`~meshprovision.db.keys.KeyRepository` over ``db``.
    """
    return KeyRepository(db)


@pytest.fixture
def template() -> TemplateConfig:
    """The minimal valid template: ``version: 1`` and nothing else.

    Returns:
        The parsed template.
    """
    return load_template_text("version: 1\n")
