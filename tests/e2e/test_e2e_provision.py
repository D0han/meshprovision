"""Factory provisioning end to end, drift repair, and ``--dry-run``/``--json``.

Every assertion in this module that touches secret material asserts its
*absence* from stdout/stderr, per the project's secret-hygiene rule.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto import weakkeys
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import ExitCode
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

    from meshprovision.crypto.keys import KeyPair
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
_SIX_DIGIT_RE = re.compile(r"(?<![\da-fA-F])\d{6}(?![\da-fA-F])")
"""Matches a bare 6-digit run (a BLE PIN candidate).

Excludes a digit run adjacent to a hex letter (not just another digit),
so an 8-char ``sha256:`` fingerprint digest -- non-secret, deliberately
printed -- is never mistaken for a PIN just because 6 of its 8
hex characters happen to be ASCII digits.
"""


def _assert_no_secrets(text: str) -> None:
    """Assert ``text`` contains no 44-char base64 blob and no bare 6-digit run."""
    assert not _BASE64_KEY_RE.search(text)
    assert not _SIX_DIGIT_RE.search(text)


def _scan_for_secrets(value: object) -> None:
    """Recursively scan a decoded JSON document for base64 keys or PINs."""
    if isinstance(value, str):
        _assert_no_secrets(value)
    elif isinstance(value, dict):
        for v in value.values():
            _scan_for_secrets(v)
    elif isinstance(value, list):
        for item in value:
            _scan_for_secrets(item)


def test_factory_provisioning_end_to_end(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "FACTORY" in result.stderr

    assert iface.localNode.localConfig.lora.region == 3  # EU_868
    assert iface.localNode.localConfig.lora.hop_limit == 3
    assert iface.localNode.localConfig.bluetooth.mode == 1  # FIXED_PIN

    public_key = bytes(iface.localNode.localConfig.security.public_key)
    private_key = bytes(iface.localNode.localConfig.security.private_key)
    assert len(public_key) == 32
    assert any(b != 0 for b in public_key)
    assert len(private_key) == 32

    assert iface.localNode.written_sections[-1] == "security"

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.node_id == "deadbe01"
    assert node.short_name == "MT00"
    assert node.long_name == "Meshtastic MT00"
    assert node.hw_model == "RAK4631"
    assert node.firmware_version == "2.7.11"
    assert node.ble_pin is not None
    assert re.fullmatch(r"\d{6}", node.ble_pin.get_secret_value())
    assert node.first_added_ts is not None
    assert node.last_updated_ts is not None
    assert node.authorized_admin_keys == ()

    keys = [KeyRecord.from_row(row) for row in loaded.keys]
    assert len(keys) == 2
    by_ref = {k.key_ref: k for k in keys}
    assert set(by_ref) == {"deadbe01_pub", "deadbe01_priv"}
    assert by_ref["deadbe01_pub"].material() == public_key
    assert by_ref["deadbe01_priv"].material() == private_key

    assert "Device public key: sha256:" in result.stderr

    _assert_no_secrets(result.stdout)
    _assert_no_secrets(result.stderr)


def test_no_reconnect_skips_the_reconnect_verify_connection(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """--no-reconnect genuinely changes behavior, not just prints a warning.

    A normal run reconnects (closes and reopens the connection) to
    verify writes against a fresh read from the device -- bus.connections
    records every backend.connect() call, so a normal run shows more
    than the one initial connection. --no-reconnect uses InPlaceSession,
    which never calls backend.connect() again at all.
    """
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--no-reconnect"], env
    )

    assert result.exit_code == 0
    assert "--no-reconnect" in result.stderr
    assert "weaker guarantee" in result.stderr
    assert len(bus.connections) == 1

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert len(loaded.nodes) == 1


def test_a_normal_run_reconnects_more_than_once(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """The baseline `--no-reconnect` is compared against: confirms the assumption above holds."""
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "--no-reconnect" not in result.stderr
    assert len(bus.connections) > 1


def test_enroll_graduates_an_observed_node_to_template_management(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED)
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--enroll"], env)

    assert result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.management is ManagementMode.TEMPLATE


def test_provision_refuses_an_archived_node(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    """A node archived via `mesh db forget` must never be silently re-provisioned.

    Checked before the enrollment gate (an archived node is more
    fundamentally off-limits than a merely-unenrolled one) and before
    any device write.
    """
    record = NodeRecord(node_id="deadbe01", archived_at=datetime(2026, 1, 1, tzinfo=UTC))
    seed_db(nodes=[record])
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "archived" in result.stderr.lower()
    assert iface.localNode.written_sections == []


def test_template_managed_node_is_unaffected_by_the_enroll_gate(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "--enroll" not in result.stderr


def test_provision_reports_a_failed_database_save_as_divergence(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))

    def _raise(*args: object, **kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ods, "write_database", _raise)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.DB)
    assert "written and verified on the device" in result.stderr
    assert "disagree" in result.stderr

    assert iface.localNode.localConfig.lora.region == 3  # EU_868
    assert iface.localNode.written_sections[-1] == "security"

    monkeypatch.undo()
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert loaded.nodes == ()

    _assert_no_secrets(result.stderr)


def test_ble_write_failure_reports_uncertain_not_a_traceback(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """A ``BLEInterface.BLEError`` mid-plan must be caught, not escape as a raw traceback.

    Regression test: ``BLEError`` subclasses plain ``Exception``, not
    ``OSError``, so it used to pass every ``except`` in
    ``apply.py``/``handle_cli_errors`` uncaught -- a raw traceback, exit
    1, and no UNCERTAIN report, silently losing any freshly generated key
    on a regenerate plan.
    """
    from meshtastic.ble_interface import BLEInterface

    bus.use(
        FakeMeshInterface(
            "deadbe01",
            fail_sections=frozenset({"lora"}),
            fail_exc=lambda _section: BLEInterface.BLEError("Error writing BLE", "write"),
        )
    )
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    # Keeps the WARNING-level structlog line ("left in an UNCERTAIN
    # STATE") out of stderr: its ISO timestamp's microseconds field is a
    # random 6-digit run that would otherwise, occasionally, collide with
    # _assert_no_secrets' bare-6-digit (BLE PIN) pattern below -- a false
    # positive unrelated to this test's own assertions, both of which are
    # satisfied by the separate ``ctx.error(...)`` line instead.
    env["MESHPROVISION_LOG_LEVEL"] = "ERROR"

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    assert "Traceback" not in result.stdout
    assert "Traceback" not in result.stderr
    assert db_fingerprint(db_path) == before

    _assert_no_secrets(result.stdout)
    _assert_no_secrets(result.stderr)


def test_declining_the_apply_prompt_aborts_before_any_write(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    # --interactive is mandatory here: CliRunner's stdin is not a TTY, so the
    # prompt would otherwise become a NonInteractiveError instead of a decline.
    result = invoke(
        runner, ["--interactive", "provision", "--port", "/dev/ttyFAKE0"], env, input="n\n"
    )

    assert result.exit_code == int(ExitCode.INTERRUPTED)
    assert "Aborted." in result.stderr
    assert iface.localNode.written_sections == []
    assert bytes(iface.localNode.localConfig.security.public_key) == b""
    assert db_fingerprint(db_path) == before


_CLI_FOREIGN_WARNING = "This node is not in the database and does not look factory-default"
"""``run_provision``'s own pre-confirmation FOREIGN warning.

Deliberately matched on the CLI's exact wording rather than the shared
"may belong to someone else" tail: ``plan.build_plan`` emits its own
FOREIGN_NODE plan warning ending in that same phrase, so the looser
substring is satisfied by the plan warning alone and would pass even
with ``run_provision``'s check inverted.
"""


def test_foreign_node_is_flagged_as_possibly_belonging_to_someone_else(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """A customized device we have never seen must be called out before any write.

    ``detect.classify`` returns FOREIGN for a device that is absent from
    the database and whose names are not factory-default. ``run_provision``
    owes the operator this warning immediately before the apply
    confirmation -- the one safety net against provisioning a stranger's
    radio.
    """
    bus.use(FakeMeshInterface("deadbe01", short_name="XR7", long_name="Someone Elses Radio"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "FOREIGN" in result.stderr
    assert _CLI_FOREIGN_WARNING in result.stderr


def test_factory_node_is_not_flagged_as_possibly_belonging_to_someone_else(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """The FOREIGN warning must not fire for a factory-default device.

    Pins the direction of the check: an inverted condition would warn
    about every factory node instead, training operators to ignore it.
    """
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "FACTORY" in result.stderr
    assert _CLI_FOREIGN_WARNING not in result.stderr


def test_zero_admin_keys_is_a_valid_outcome_never_repaired(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    first = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    node = NodeRecord.from_row(loaded.nodes[0])
    assert node.authorized_admin_keys == ()

    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert second.exit_code == 0
    assert "No changes needed." in second.stderr


def test_drift_repair_renames_back_and_updates_role(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    node_record = NodeRecord(
        node_id="deadbe01",
        short_name="MT07",
        long_name="Meshtastic MT07",
        hw_model="RAK4631",
        role="ROUTER",
        region="EU_868",
        management=ManagementMode.TEMPLATE,
    )
    pub_record, priv_record = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    seed_db(nodes=[node_record], keys=[pub_record, priv_record])

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="be01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.device.role = 2  # ROUTER

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "Drift detected:" in result.stderr
    assert re.search(r"name\.short_name: recorded=MT07, observed=be01", result.stderr)

    assert iface.user["shortName"] == "MT07"
    assert iface.localNode.localConfig.device.role == 0  # CLIENT (template default)

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.role == "CLIENT"
    assert persisted.last_updated_ts is not None
    assert persisted.last_updated_ts != node_record.first_added_ts

    keys = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(keys["deadbe01_pub"]).material() == kp.public
    assert bytes(iface.localNode.localConfig.security.public_key) == kp.public


def test_rename_reallocates_a_fresh_name_for_an_already_provisioned_node(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """``--rename`` is the one flag that makes ``allocate_names`` actually run again.

    Without it (see ``test_zero_admin_keys_is_a_valid_outcome_never_repaired``
    and ``test_drift_repair_renames_back_and_updates_role`` above), a second
    provisioning run of an already-known node keeps its recorded name --
    ``allocate_names`` returns ``(None, None)`` and ``build_plan`` falls back
    to the database's current name. Nothing in the e2e suite passed
    ``--rename`` itself before this test, so the "no change" behavior of the
    other tests was never actually contrasted against the opt-in case.
    """
    bus.use(FakeMeshInterface("deadbe01"))

    first = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    node = NodeRecord.from_row(loaded.nodes[0])
    assert node.short_name == "MT00"

    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--rename"], env)
    assert second.exit_code == 0
    assert "No changes needed." not in second.stderr

    reloaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    renamed = NodeRecord.from_row(reloaded.nodes[0])
    assert renamed.short_name != "MT00"
    assert re.fullmatch(r"MT[0-9A-Z]{2}", renamed.short_name)
    assert renamed.long_name == f"Meshtastic {renamed.short_name}"


def test_stale_db_key_is_corrected_by_adopting_the_devices_reported_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Regression test for the `adopt_device_key` persistence gap (firmware #7449).

    A plan that decides to adopt the device's reported key rather than
    overwrite it (because the Keys sheet disagrees with what the device
    holds) must actually correct the Keys sheet -- not just print a
    warning and leave the stale row in place forever.
    """
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    iface = bus.use(FakeMeshInterface("deadbe01"))

    first = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first.exit_code == 0

    device_public_key = bytes(iface.localNode.localConfig.security.public_key)
    device_private_key = bytes(iface.localNode.localConfig.security.private_key)

    loaded = ods.load_database(db_path)
    node_record = NodeRecord.from_row(loaded.nodes[0])
    stale = keypair_factory()
    stale_pub, stale_priv = KeyRecord.for_keypair("deadbe01", stale, origin=KeyOrigin.CAPTURED)
    seed_db(nodes=[node_record], keys=[stale_pub, stale_priv])

    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert second.exit_code == 0
    assert "#7449" in second.stderr

    # The device's own key material is never touched -- only adopted into the DB.
    assert bytes(iface.localNode.localConfig.security.public_key) == device_public_key
    assert bytes(iface.localNode.localConfig.security.private_key) == device_private_key
    assert device_public_key != stale.public

    loaded_after = ods.load_database(db_path)
    keys_after = {row["key_ref"]: row for row in loaded_after.keys}
    assert KeyRecord.from_row(keys_after["deadbe01_pub"]).material() == device_public_key
    assert KeyRecord.from_row(keys_after["deadbe01_priv"]).secret().reveal() == device_private_key

    _assert_no_secrets(second.stdout)
    _assert_no_secrets(second.stderr)


def test_repair_with_no_admin_nodes_template_preserves_existing_admin_keys(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    admin_kp = keypair_factory()
    node_record = NodeRecord(
        node_id="deadbe01",
        short_name="MT07",
        long_name="Meshtastic MT07",
        hw_model="RAK4631",
        role="ROUTER",
        region="EU_868",
        authorized_admin_keys=("ADMIN1_pub",),
        management=ManagementMode.TEMPLATE,
    )
    pub_record, priv_record = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    admin_pub_record, admin_priv_record = KeyRecord.for_keypair(
        "ADMIN1", admin_kp, origin=KeyOrigin.IMPORTED
    )
    seed_db(
        nodes=[node_record],
        keys=[pub_record, priv_record, admin_pub_record, admin_priv_record],
    )

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="be01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)
    iface.localNode.localConfig.device.role = 2  # ROUTER

    # env's default template has admin_nodes: [] -- resolve_admin_keys therefore
    # has no opinion, and ChangePlan.to_record() must leave the node's existing
    # authorized_admin_keys untouched rather than wiping them.
    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "Drift detected:" in result.stderr

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.authorized_admin_keys == ("ADMIN1_pub",)


def test_revoked_live_admin_key_is_dropped_from_the_record(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    admin2_kp = keypair_factory()
    weak_public = weakkeys.SMALL_ORDER_POINTS[3]
    node_record = NodeRecord(
        node_id="deadbe01",
        short_name="MT07",
        long_name="Meshtastic MT07",
        hw_model="RAK4631",
        role="ROUTER",
        region="EU_868",
        authorized_admin_keys=("ADMIN1_pub", "ADMIN2_pub"),
        management=ManagementMode.TEMPLATE,
    )
    pub_record, priv_record = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    admin2_pub, admin2_priv = KeyRecord.for_keypair("ADMIN2", admin2_kp, origin=KeyOrigin.IMPORTED)
    seed_db(
        nodes=[node_record],
        keys=[
            pub_record,
            priv_record,
            KeyRecord.from_material(
                "ADMIN1", KeyType.ADMIN_PUBLIC, weak_public, origin=KeyOrigin.IMPORTED
            ),
            admin2_pub,
            admin2_priv,
        ],
    )

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="be01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(weak_public)
    iface.localNode.localConfig.security.admin_key.append(admin2_kp.public)
    iface.localNode.localConfig.device.role = 2  # ROUTER

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    _assert_no_secrets(result.stderr)

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.authorized_admin_keys == ("ADMIN2_pub",)
    assert [bytes(k) for k in iface.localNode.localConfig.security.admin_key] == [admin2_kp.public]

    # The headline symptom: a second run must no longer report admin_keys drift
    # between the (now narrowed) row and the (now cleaned) device.
    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert second.exit_code == 0
    _assert_no_secrets(second.stderr)
    assert "admin_keys" not in second.stderr


def test_dry_run_writes_nothing(runner: CliRunner, env: dict[str, str], bus: DeviceBus) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0
    assert result.stdout.strip() != ""
    assert iface.localNode.written_sections == []
    assert bytes(iface.localNode.localConfig.security.public_key) == b""
    assert db_fingerprint(db_path) == before


def test_json_plan_is_fully_redacted(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert set(document) >= {"detection", "drifts", "plan"}
    assert document["plan"]["key_plan"]["regenerate"] is True
    assert document["plan"]["ble_pin_set"] is True

    _scan_for_secrets(document)


# ---------------------------------------------------------------------------
# Round 37 aspect 1 finding #1: CVE-2025-52464 firmware-window convergence.
# ---------------------------------------------------------------------------

_NO_SECURITY_CHANGE_LINES = (
    "security.private_key: regenerate",
    "security.public_key: adopt the device's reported key",
)


def _keys_snapshot(db_path: Path) -> list[tuple[str, bytes, KeyOrigin | None]]:
    loaded = ods.load_database(db_path)
    return sorted(
        (record.key_ref, record.material(), record.origin)
        for record in (KeyRecord.from_row(row) for row in loaded.keys)
    )


@pytest.mark.parametrize(
    ("firmware", "lockdown"),
    [
        pytest.param(
            fw, is_lockdown, id=f"{fw or 'blank'}-{'lockdown' if is_lockdown else 'plain'}"
        )
        for fw in ("2.7.11", "2.6.11", "2.6.10", "2.6.0", "2.5.0", "")
        for is_lockdown in (False, True)
    ],
)
def test_provision_is_idempotent(
    firmware: str,
    lockdown: bool,
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    """A second, unchanged ``mesh provision`` run is a true no-op, on every firmware.

    Regression test for Round 37 aspect 1 finding #1, the HIGH this
    round exists to close: CVE-2025-52464-window firmware (2.5.0-2.6.10)
    used to regenerate -- and so reboot -- the node's key on *every*
    ``mesh provision`` run, because nothing distinguished a host-
    generated key from a device-observed one. ``is_host_generated_key``
    fixes that: once a key this host generated is recorded with
    ``origin=generated``, a second run on the same (still in-window)
    firmware converges instead of regenerating again. Parametrized over
    the CVE window's boundaries plus a blank/clean control, crossed with
    a plain and a lockdown (``security.is_managed``) template, since S1
    (a later batch) gates admin-bearing key changes and this node must
    stay outside that gate either way.

    Scope note: the fake device does not model firmware refusing local
    writes once ``is_managed`` is set -- this test only proves the
    planner itself is a fixed point, not the on-wire lockdown behavior.
    """
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    extra_args: list[str] = []
    if lockdown:
        bus.use(FakeMeshInterface("aaaa0001"))
        bootstrap = invoke(
            runner,
            ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN1", "--yes"],
            env,
        )
        assert bootstrap.exit_code == 0
        env["MESHPROVISION_TEMPLATE_PATH"] = str(
            write_template(admin_nodes=["ADMIN1"], security={"is_managed": True})
        )
        extra_args = ["--allow-lockdown"]
    else:
        env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=[]))

    iface = bus.use(FakeMeshInterface("deadbe01", firmware_version=firmware))

    run1 = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", *extra_args], env)
    assert run1.exit_code == 0

    key1 = bytes(iface.security.public_key)
    keys1 = _keys_snapshot(db_path)
    persisted_config = iface.localNode.localConfig.SerializeToString()
    user1 = dict(iface.user)

    iface.localNode.written_sections.clear()

    run2 = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", *extra_args], env)

    assert run2.exit_code == 0
    assert iface.localNode.written_sections == []
    assert iface.user == user1
    assert bytes(iface.security.public_key) == key1
    assert _keys_snapshot(db_path) == keys1
    assert iface.localNode.localConfig.SerializeToString() == persisted_config
    for line in _NO_SECURITY_CHANGE_LINES:
        assert line not in run2.stderr
    assert "No changes needed." in run2.stderr

    if weakkeys.is_vulnerable_firmware(firmware):
        assert "CVE-2025-52464 window" in run2.stderr
        assert "generated by meshprovision" in run2.stderr


def test_lockdown_plan_with_a_failing_lora_write_never_locks_the_node(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    """A lockdown plan whose ``lora`` write fails must never reach ``security``.

    Regression test for Round 37 aspect 4 finding E2, the HIGH this batch
    fixes: ``apply_plan`` used to keep writing after a failure, including
    ``security`` -- which can set ``is_managed=true`` and lock the node --
    even though an earlier section already failed.
    """
    bus.use(FakeMeshInterface("aaaa0001"))
    bootstrap = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN1", "--yes"],
        env,
    )
    assert bootstrap.exit_code == 0
    env["MESHPROVISION_TEMPLATE_PATH"] = str(
        write_template(admin_nodes=["ADMIN1"], security={"is_managed": True})
    )
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    iface = bus.use(FakeMeshInterface("deadbe01", fail_sections=frozenset({"lora"})))

    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--allow-lockdown"],
        env,
    )

    assert result.exit_code == ExitCode.PROVISIONING
    assert "UNCERTAIN" in result.stderr
    assert "the database was NOT updated" in result.stderr
    not_written_line = next(
        line for line in result.stderr.splitlines() if line.startswith("error: Not written")
    )
    assert "security" in not_written_line
    assert "was not locked" in result.stderr

    assert iface.security.is_managed is False
    assert iface.admin_keys == ()
    assert bytes(iface.security.private_key) == b""
    assert "security" not in iface.localNode.written_sections
    assert db_fingerprint(db_path) == before


def test_legacy_blank_origin_key_on_cve_window_firmware_still_regenerates(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A recorded key with unknown provenance (``origin=None``) never counts as host-generated.

    Fail-safe: a row written before the ``origin`` column existed must
    still be treated as potentially device-generated on CVE-window
    firmware, exactly like today's behavior, until this host itself
    regenerates and records it.
    """
    stale = keypair_factory()
    pub, priv = KeyRecord.for_keypair("deadbe01", stale, origin=KeyOrigin.GENERATED)
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)],
        keys=[pub.with_origin(None), priv.with_origin(None)],
    )
    iface = bus.use(FakeMeshInterface("deadbe01", firmware_version="2.6.0"))
    iface.localNode.localConfig.security.public_key = stale.public
    iface.localNode.localConfig.security.private_key = stale.private.reveal()

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert bytes(iface.security.public_key) != stale.public

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(rows["deadbe01_pub"]).origin is KeyOrigin.GENERATED


def test_captured_origin_key_on_cve_window_firmware_still_regenerates(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A ``captured`` key is a device-generated key, by definition -- never suppressed.

    Only ``origin=generated`` can suppress the CVE-2025-52464
    firmware-window finding. A key ``mesh adopt`` (or the ``#7449``
    adopt path) captured from a device came from the device's own RNG,
    exactly the failure mode the CVE describes, so it must keep
    regenerating on in-window firmware just like today.
    """
    stale = keypair_factory()
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)],
        keys=list(KeyRecord.for_keypair("deadbe01", stale, origin=KeyOrigin.CAPTURED)),
    )
    iface = bus.use(FakeMeshInterface("deadbe01", firmware_version="2.6.0"))
    iface.localNode.localConfig.security.public_key = stale.public
    iface.localNode.localConfig.security.private_key = stale.private.reveal()

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert bytes(iface.security.public_key) != stale.public

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(rows["deadbe01_pub"]).origin is KeyOrigin.GENERATED


def test_provision_captures_a_proven_private_key_for_an_ordinary_node(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """A node with a public-only key gets its private key recorded once proven (CC-D1 Option A).

    Not special-cased to admin-bearing nodes: any node whose Keys row
    has a public key but no recorded private key -- for example, one
    ``mesh adopt`` enrolled while the device hid its private key -- gets
    that private key captured the moment the device proves it holds the
    matching material, the same way ``mesh provision``/``mesh adopt``
    already record one for every other captured key.
    """
    bus.use(FakeMeshInterface("deadbe01"))

    first = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first.exit_code == 0

    db_path = Path(env["MESHPROVISION_DB_PATH"])
    loaded = ods.load_database(db_path)
    rows = {row["key_ref"]: row for row in loaded.keys}
    node_row = loaded.nodes[0]
    pub_only = KeyRecord.from_row(rows["deadbe01_pub"])
    expected_private = KeyRecord.from_row(rows["deadbe01_priv"]).material()

    # Simulate a node whose private key was never captured -- e.g. one
    # `mesh adopt` enrolled while the device hid its private key.
    ods.write_database(db_path, nodes=[node_row], keys=[pub_only.to_row()], backup=False)

    second = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert second.exit_code == 0
    assert "No changes needed." in second.stderr
    assert "Recorded the device's private key" in second.stderr

    loaded2 = ods.load_database(db_path)
    rows2 = {row["key_ref"]: row for row in loaded2.keys}
    priv = KeyRecord.from_row(rows2["deadbe01_priv"])
    assert priv.material() == expected_private
    assert priv.origin is KeyOrigin.CAPTURED


def test_provision_fills_a_stale_alias_private_key_when_proven(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """An existing stale alias ``_priv`` row is filled once the alias's ``_pub`` is proven.

    CC-D1 Option A also fills any EXISTING alias private row that is
    stale -- not just the node's own ``<hex>_priv`` row -- when the
    alias's public row holds the same material the device just proved.
    """
    kp = keypair_factory()
    stale_kp = keypair_factory()  # unrelated material -- makes ADMIN1_priv stale
    node_pub, node_priv = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.GENERATED)
    alias_pub = KeyRecord.from_material(
        "ADMIN1", KeyType.ADMIN_PUBLIC, kp.public, origin=KeyOrigin.IMPORTED
    )
    alias_stale_priv = KeyRecord.from_material(
        "ADMIN1", KeyType.ADMIN_PRIVATE, stale_kp.private, origin=KeyOrigin.IMPORTED
    )
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)],
        keys=[node_pub, node_priv, alias_pub, alias_stale_priv],
    )

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "Filled the stale private key recorded for alias 'ADMIN1'" in result.stderr

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    alias_priv_after = KeyRecord.from_row(rows["ADMIN1_priv"])
    assert alias_priv_after.material() == kp.private.reveal()
    assert alias_priv_after.origin is KeyOrigin.CAPTURED


def test_provision_never_creates_a_new_alias_private_key_row(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """An alias with no existing private row never gets one created (CC-D1 Option A / CC #5.2).

    The proven-private-key capture only ever fills an alias's *existing*
    ``_priv`` row; an alias that has a public row but was never given a
    private one -- the normal shape for an alias registered via
    ``mesh admin import`` -- must stay that way.
    """
    kp = keypair_factory()
    node_pub, node_priv = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.GENERATED)
    alias_pub = KeyRecord.from_material(
        "ADMIN1", KeyType.ADMIN_PUBLIC, kp.public, origin=KeyOrigin.IMPORTED
    )
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)],
        keys=[node_pub, node_priv, alias_pub],
    )

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "alias" not in result.stderr.lower()

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert "ADMIN1_priv" not in rows


def test_generated_origin_with_mismatched_private_key_still_regenerates(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """``is_host_generated_key`` verifies material, not just the ``origin`` label.

    A ``GENERATED`` public-key row whose recorded private key does not
    actually derive it (a hand edit, or a stale row some other bug left
    behind) must not be trusted -- the predicate must still be able to
    tell this key's true provenance is unconfirmed, so CVE-window
    firmware still regenerates it.
    """
    live_kp = keypair_factory()
    other_kp = keypair_factory()
    pub, _own_priv = KeyRecord.for_keypair("deadbe01", live_kp, origin=KeyOrigin.GENERATED)
    _other_pub, mismatched_priv = KeyRecord.for_keypair(
        "deadbe01", other_kp, origin=KeyOrigin.GENERATED
    )
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)],
        keys=[pub, mismatched_priv],
    )
    iface = bus.use(FakeMeshInterface("deadbe01", firmware_version="2.6.0"))
    iface.localNode.localConfig.security.public_key = live_kp.public
    iface.localNode.localConfig.security.private_key = live_kp.private.reveal()

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert bytes(iface.security.public_key) != live_kp.public

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(rows["deadbe01_pub"]).origin is KeyOrigin.GENERATED
