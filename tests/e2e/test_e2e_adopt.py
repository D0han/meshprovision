"""``mesh adopt``: strictly read-only device inventory, recorded as observed."""

from __future__ import annotations

import base64
import json
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from meshtastic.protobuf import apponly_pb2, clientonly_pb2, config_pb2

from meshprovision.crypto import redact
from meshprovision.crypto.keys import encode_key
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.observed_keys import observed_key_ref
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import ExitCode
from tests.e2e.conftest import FakeMeshInterface, db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    import respx
    from click.testing import CliRunner

    from meshprovision.crypto.keys import KeyPair
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


def test_adopt_never_writes_to_the_device(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    admin_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert iface.localNode.written_sections == []


def test_fresh_adopt_persists_an_observed_record(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.node_id == "deadbe01"
    assert node.management is ManagementMode.OBSERVED
    assert node.short_name == "AB01"
    assert node.long_name == "Adopted Node 01"
    assert node.hw_model == "RAK4631"
    assert node.firmware_version == "2.7.11"


def test_adopted_device_name_with_terminal_escape_is_escaped_on_db_list(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """Regression test for Round 37's terminal-escape-injection fix (S6/T9c).

    S6 deliberately does not sanitize a device-reported name at adopt
    ingress (that would cause rename churn against the device's own
    truth) -- the DB row keeps the raw name, and the render-layer sink
    (``mesh db list``) is the one place responsible for escaping it
    before it reaches the terminal. This pins that decision from both
    sides: the DB cell holds the raw name, the printed table does not.

    Uses a bidi right-to-left-override character rather than a raw ESC
    byte for the "DB holds it raw" half of this test: a C0/C1/DEL
    control byte does not survive an ODS save/load round-trip at all in
    this environment (odfpy/expat silently replace it with U+FFFD on
    reload, independent of this fix -- confirmed by direct
    ``odf.opendocument`` reproduction), so asserting the exact raw ESC
    byte in the reloaded row would test an ODS behavior, not this fix.
    The escape-at-render half is still exercised on a real ESC payload
    below via ``ctx``'s own sinks (see ``test_status_merge.py`` and
    ``test_cli_common.py``), which never touch the ODS layer.
    """
    payload = "X‮evil"
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name=payload))

    adopt_result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert adopt_result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert nodes[0].long_name == payload

    list_result = invoke(runner, ["db", "list"], env)
    assert list_result.exit_code == 0
    assert "‮" not in list_result.stdout
    assert "‮" not in list_result.stderr
    assert "\\u202e" in list_result.stderr


def test_dry_run_writes_nothing_to_the_database(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0
    assert db_fingerprint(db_path) == before
    assert "deadbe01" in result.stderr


def test_dry_run_registers_no_keys_either(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, keypair_factory: Callable[[], KeyPair]
) -> None:
    """--dry-run must not mint an observed ref or register the node's own key."""
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    kp = keypair_factory()
    stray_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(stray_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0
    assert db_fingerprint(db_path) == before


def test_dry_run_self_admin_key_states_its_own_ref_not_an_observed_one(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, keypair_factory: Callable[[], KeyPair]
) -> None:
    """Regression test for Round 35's adopt-flow Finding 2.

    A device that lists its own public key on its own security.adminKey
    (the standard single-admin-node fleet layout) resolves that key to
    its own f"{node_id}_pub" ref on a real run -- the preview must say
    so, not claim (as the pre-write classification alone would) that a
    synthetic observed-* ref will be minted and offer an
    `mesh admin import` command for a key that is never actually filed
    that way.
    """
    kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(kp.public)

    result = invoke(
        runner, ["adopt", "--port", "/dev/ttyFAKE0", "--dry-run", "--show-admin-keys"], env
    )

    assert result.exit_code == 0
    assert "deadbe01_pub" in result.stderr
    assert "is this node's own public key" in result.stderr
    assert "will be filed under" not in result.stderr
    assert "mesh admin import" not in result.stderr


def test_dry_run_warns_when_adopt_would_overwrite_existing_key_material(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Regression test for Round 35's adopt-flow Finding 3.

    A re-keyed, re-flashed, or spoofed device silently overwrote the
    Keys sheet's existing (and for _priv, otherwise unrecoverable)
    material, with no preview surface an operator could have caught it
    on -- --dry-run's output was byte-identical whether or not this
    adopt would replace different key material underneath an existing
    node. It must now say so, and say so before any write happens.
    """
    old_kp = keypair_factory()
    new_kp = keypair_factory()
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01")],
        keys=[
            *KeyRecord.for_keypair("deadbe01", old_kp, origin=KeyOrigin.CAPTURED),
        ],
    )
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = new_kp.public
    iface.localNode.localConfig.security.private_key = new_kp.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0
    assert db_fingerprint(db_path) == before
    assert "deadbe01_pub already holds different key material" in result.stderr
    assert "deadbe01_priv already holds different key material" in result.stderr


def test_adopt_registers_the_nodes_own_public_and_private_key(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, keypair_factory: Callable[[], KeyPair]
) -> None:
    """A device exposing both key halves gets both Keys sheet rows."""
    kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys_by_ref = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert set(keys_by_ref) == {"deadbe01_pub", "deadbe01_priv"}
    assert keys_by_ref["deadbe01_pub"].material() == kp.public
    assert keys_by_ref["deadbe01_priv"].secret().reveal() == kp.private.reveal()
    node = NodeRecord.from_row(loaded.nodes[0])
    assert node.public_key_ref == "deadbe01_pub"
    assert node.private_key_ref == "deadbe01_priv"


def test_adopt_registers_only_the_nodes_public_key_when_private_is_absent(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, keypair_factory: Callable[[], KeyPair]
) -> None:
    """A device exposing only its public key gets only the _pub row."""
    kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys_by_ref = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert set(keys_by_ref) == {"deadbe01_pub"}
    assert keys_by_ref["deadbe01_pub"].material() == kp.public


def test_adopting_the_true_owner_renames_a_stale_observed_ref(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Adopting node A first, then the key's true owner B, renames A's ref to B's."""
    kp = keypair_factory()
    observed_ref = observed_key_ref(kp.public)
    seed_db(
        nodes=[NodeRecord(node_id="aaaa0001", authorized_admin_keys=(observed_ref,))],
        keys=[
            KeyRecord.from_material(
                observed_ref.removesuffix("_pub"),
                KeyType.ADMIN_PUBLIC,
                kp.public,
                origin=KeyOrigin.IMPORTED,
            )
        ],
    )

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes_by_id = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert nodes_by_id["aaaa0001"].authorized_admin_keys == ("deadbe01_pub",)
    key_refs = {row["key_ref"] for row in loaded.keys}
    assert observed_ref not in key_refs
    assert "deadbe01_pub" in key_refs


def test_adopting_a_self_admining_node_does_not_persist_the_ref_it_just_deleted(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Regression test for Round 35's adopt-flow Finding 1.

    A node whose own public key is *also* listed on its own
    security.admin_key (the standard single-admin-node fleet layout) must
    not end up with authorized_admin_keys pointing at the observed-* ref
    that this same adopt's own_keypair-registration + adopt_canonical_ref
    reconciliation just deleted. Reproduces the exact scenario from the
    prior test above, but with the device also self-admining -- which is
    the one combination report.admin_keys' pre-write classification can't
    see past.
    """
    kp = keypair_factory()
    observed_ref = observed_key_ref(kp.public)
    seed_db(
        nodes=[NodeRecord(node_id="aaaa0001", authorized_admin_keys=(observed_ref,))],
        keys=[
            KeyRecord.from_material(
                observed_ref.removesuffix("_pub"),
                KeyType.ADMIN_PUBLIC,
                kp.public,
                origin=KeyOrigin.IMPORTED,
            )
        ],
    )

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = kp.public
    iface.localNode.localConfig.security.private_key = kp.private.reveal()
    iface.localNode.localConfig.security.admin_key.append(kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes_by_id = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert nodes_by_id["aaaa0001"].authorized_admin_keys == ("deadbe01_pub",)
    # The node being adopted must resolve its own admin key to its own
    # real ref, not the observed-* ref that was just deleted out from
    # under it.
    assert nodes_by_id["deadbe01"].authorized_admin_keys == ("deadbe01_pub",)
    key_refs = {row["key_ref"] for row in loaded.keys}
    assert observed_ref not in key_refs
    assert "deadbe01_pub" in key_refs

    verify_result = invoke(runner, ["db", "verify"], env)
    assert verify_result.exit_code == 0


def test_refuses_a_template_managed_node_without_force(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)
    db_path = seed_db(nodes=[record])
    before = db_fingerprint(db_path)
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code != 0
    assert db_fingerprint(db_path) == before
    assert "--force" in result.stderr


def test_refuses_an_archived_node_even_with_force(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    """An archived node must never be silently re-adopted, not even with --force.

    Distinct from the template-managed refusal above: --force exists
    specifically to bypass *that* check, but archiving is a deliberate
    decommission decision that a different command (mesh db forget) made
    -- mesh adopt reusing --force to also silently un-archive a node
    would be a confusing side channel, so there is no bypass here at all.
    """
    record = NodeRecord(node_id="deadbe01", archived_at=datetime(2026, 1, 1, tzinfo=UTC))
    db_path = seed_db(nodes=[record])
    before = db_fingerprint(db_path)
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--force"], env)

    assert result.exit_code != 0
    assert db_fingerprint(db_path) == before
    assert "archived" in result.stderr.lower()


def test_force_re_adopts_and_demotes_with_explicit_confirmation(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.TEMPLATE)
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--force"], env)

    assert result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    persisted = NodeRecord.from_row(loaded.nodes[0])
    assert persisted.management is ManagementMode.OBSERVED


# --- admin-key rotation refusal (C37-1) ------------------------------------


def _seed_canonicalized_admin_node(seed_db: Callable[..., Path], *, admin_kp: KeyPair) -> None:
    """Seed ``aaaa0001`` authorizing an observed ref for ``admin_kp``'s material.

    Shared setup for the tests below: adopting ``deadbe01`` reporting
    ``admin_kp`` canonicalizes this observed ref to ``deadbe01_pub``,
    which is what makes ``deadbe01`` admin-bearing -- the standard
    brownfield flow the finding reproduces its probe scenario against.
    """
    observed_ref = observed_key_ref(admin_kp.public)
    seed_db(
        nodes=[NodeRecord(node_id="aaaa0001", authorized_admin_keys=(observed_ref,))],
        keys=[
            KeyRecord.from_material(
                observed_ref.removesuffix("_pub"),
                KeyType.ADMIN_PUBLIC,
                admin_kp.public,
                origin=KeyOrigin.IMPORTED,
            )
        ],
    )


def test_adopt_refuses_to_rotate_an_observed_admin_bearing_nodes_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """The probe scenario (CONSISTENCY-CHECK.md 4.1): no flag bypasses this.

    ``aaaa0001`` authorizes an observed ref; adopting ``deadbe01``
    reporting that key canonicalizes it to ``deadbe01_pub``, making
    ``deadbe01`` admin-bearing under ``node_key_admin_refs``. A second
    adopt of ``deadbe01`` by an impostor reporting a fresh keypair must
    be refused outright -- with no flag, not even ``--yes`` -- and must
    not touch the database at all, not even to prompt for confirmation.
    """
    admin_kp = keypair_factory()
    _seed_canonicalized_admin_node(seed_db, admin_kp=admin_kp)

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = admin_kp.public
    iface.localNode.localConfig.security.private_key = admin_kp.private.reveal()
    first_adopt = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first_adopt.exit_code == 0

    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = ods.load_database(db_path)

    impostor = bus.use(FakeMeshInterface("deadbe01"))
    fresh = keypair_factory()
    impostor.localNode.localConfig.security.public_key = fresh.public
    impostor.localNode.localConfig.security.private_key = fresh.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "admin key" in result.stderr.lower()
    assert "mesh admin import --overwrite deadbe01=" in result.stderr
    assert redact.fingerprint(fresh.public) in result.stderr
    assert not _BASE64_KEY_RE.search(result.stderr)
    assert impostor.localNode.written_sections == []

    after = ods.load_database(db_path)
    assert after.nodes == before.nodes
    assert after.keys == before.keys


def test_adopt_force_does_not_bypass_admin_key_rotation_refusal_on_a_template_node(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """``--force`` still demotes a TEMPLATE node, but never bypasses this refusal.

    ``admin bootstrap`` self-refs ``aaaa0001`` as its own admin, leaving
    it ``management=TEMPLATE``. ``--force`` is the flag that normally
    lets ``mesh adopt`` re-adopt (demote) a TEMPLATE-managed node -- it
    must not also be read as authorization to rotate the admin key that
    node backs.
    """
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=[]))
    bus.use(FakeMeshInterface("aaaa0001"))
    bootstrap = invoke(runner, ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert bootstrap.exit_code == 0

    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["aaaa0001"]))
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = ods.load_database(db_path)

    impostor = bus.use(FakeMeshInterface("aaaa0001"))
    fresh = keypair_factory()
    impostor.localNode.localConfig.security.public_key = fresh.public
    impostor.localNode.localConfig.security.private_key = fresh.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--force", "--yes"], env)

    assert result.exit_code == ExitCode.PROVISIONING
    assert "admin key" in result.stderr.lower()
    assert not _BASE64_KEY_RE.search(result.stderr)
    assert impostor.localNode.written_sections == []

    after = ods.load_database(db_path)
    assert after.nodes == before.nodes
    assert after.keys == before.keys


def test_adopt_from_backup_refuses_to_rotate_an_admin_bearing_nodes_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
    tmp_path: Path,
) -> None:
    """The same refusal applies to ``--from-backup``, no device needed.

    Reuses the probe scenario's canonicalized admin-bearing ``deadbe01``,
    then claims it from a backup profile file carrying a different
    keypair -- proving the refusal is not merely a property of the
    live-device write path.
    """
    admin_kp = keypair_factory()
    _seed_canonicalized_admin_node(seed_db, admin_kp=admin_kp)

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = admin_kp.public
    iface.localNode.localConfig.security.private_key = admin_kp.private.reveal()
    first_adopt = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first_adopt.exit_code == 0

    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = ods.load_database(db_path)

    fresh = keypair_factory()
    cfg = _write_profile_cfg(
        tmp_path / "impostor.cfg", public_key=fresh.public, private_key=fresh.private.reveal()
    )

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!deadbe01", "--no-lookup", "--yes"],
        env,
    )

    assert result.exit_code == ExitCode.PROVISIONING
    assert "admin key" in result.stderr.lower()
    assert not _BASE64_KEY_RE.search(result.stderr)

    after = ods.load_database(db_path)
    assert after.nodes == before.nodes
    assert after.keys == before.keys


def test_adopt_reporting_the_same_key_as_an_admin_bearing_node_succeeds(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Re-adopting the genuine device, reporting its own unchanged key, is unaffected."""
    admin_kp = keypair_factory()
    _seed_canonicalized_admin_node(seed_db, admin_kp=admin_kp)

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = admin_kp.public
    iface.localNode.localConfig.security.private_key = admin_kp.private.reveal()
    first_adopt = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first_adopt.exit_code == 0

    same_device = bus.use(FakeMeshInterface("deadbe01"))
    same_device.localNode.localConfig.security.public_key = admin_kp.public
    same_device.localNode.localConfig.security.private_key = admin_kp.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys_by_ref = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert keys_by_ref["deadbe01_pub"].material() == admin_kp.public
    assert keys_by_ref["deadbe01_priv"].secret().reveal() == admin_kp.private.reveal()


def test_adopt_still_re_adopts_a_non_admin_node_with_a_different_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Guard: this refusal must not regress the ordinary re-key/re-flash/spoof case.

    ``deadbe01`` here backs no admin ref at all (``node_key_admin_refs``
    is empty), so a differing key still adopts normally -- with the
    pre-existing ``_key_overwrite_warnings`` warning, unchanged.
    """
    old_kp = keypair_factory()
    new_kp = keypair_factory()
    seed_db(
        nodes=[NodeRecord(node_id="deadbe01")],
        keys=[*KeyRecord.for_keypair("deadbe01", old_kp, origin=KeyOrigin.CAPTURED)],
    )

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = new_kp.public
    iface.localNode.localConfig.security.private_key = new_kp.private.reveal()

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "deadbe01_pub already holds different key material" in result.stderr
    assert "deadbe01_priv already holds different key material" in result.stderr
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys_by_ref = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    assert keys_by_ref["deadbe01_pub"].material() == new_kp.public
    assert keys_by_ref["deadbe01_priv"].secret().reveal() == new_kp.private.reveal()


def test_unregistered_admin_key_default_hides_material(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    admin_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_unregistered_admin_key_show_admin_keys_prints_import_command(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    admin_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(admin_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--show-admin-keys"], env)

    assert result.exit_code == 0
    assert "mesh admin import" in result.stderr
    assert base64.b64encode(admin_kp.public).decode("ascii") in result.stderr


def test_show_admin_keys_never_crashes_on_a_malformed_length_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
) -> None:
    """Regression test: a malformed admin key must degrade, never crash the command.

    detect.py applies no length check when reading security.admin_key
    off the device, so a device reporting a corrupted (non-32-byte)
    admin key is reachable in practice. crypto.keys.encode_key()
    validates length and raises on a mismatch -- --show-admin-keys must
    catch that per key, not let it abort the whole report.
    """
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(b"\x01\x02\x03")

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--show-admin-keys"], env)

    assert result.exit_code == 0
    assert "cannot render an import command" in result.stderr
    assert "mesh admin import" not in result.stderr


def test_show_admin_keys_degrades_per_key_not_for_the_whole_report(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A malformed key must not suppress the import command for the keys after it.

    ``_render_admin_key_lines`` promises degrading *per key*: the
    malformed key is reported as unrenderable and the loop continues. A
    ``continue``-to-``break`` regression would truncate the paste-ready
    import commands for every subsequent unregistered key, which is
    exactly what ``--show-admin-keys`` exists to produce.
    """
    good_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(b"\x01\x02\x03")
    iface.localNode.localConfig.security.admin_key.append(good_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--show-admin-keys"], env)

    assert result.exit_code == 0
    assert "cannot render an import command" in result.stderr
    assert "mesh admin import" in result.stderr
    assert base64.b64encode(good_kp.public).decode("ascii") in result.stderr


def test_adopt_recognizes_a_pre_imported_friends_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    friend_kp = keypair_factory()
    import_result = invoke(
        runner,
        ["admin", "import", f"FRIEND={base64.b64encode(friend_kp.public).decode()}"],
        env,
    )
    assert import_result.exit_code == 0

    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(friend_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["admin_keys"][0]["refs"] == ["FRIEND_pub"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ("FRIEND_pub",)


def test_adopt_discover_then_import_then_reconcile_a_friends_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    friend_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(friend_kp.public)

    first = invoke(
        runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json", "--show-admin-keys"], env
    )
    assert first.exit_code == 0
    first_doc = json.loads(first.stdout)
    assert first_doc["admin_keys"][0]["refs"] == []
    revealed_b64 = first_doc["admin_keys"][0]["material"]
    assert base64.b64decode(revealed_b64) == friend_kp.public

    # mesh adopt auto-registers a not-yet-recognized admin key under a
    # synthetic, content-addressed observed-* ref -- never leaving it
    # dangling in authorized_admin_keys or unregistered_admin_keys.
    observed_ref = observed_key_ref(friend_kp.public)
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    adopted = NodeRecord.from_row(loaded.nodes[0])
    assert adopted.authorized_admin_keys == (observed_ref,)
    assert adopted.unregistered_admin_keys == ()

    import_result = invoke(runner, ["admin", "import", f"FRIEND={revealed_b64}"], env)
    assert import_result.exit_code == 0

    # mesh admin import reconciles immediately: the observed-* ref is
    # renamed to the real one on every node that carried it, and the
    # superseded observed-* Keys row is gone -- no second adopt needed.
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ("FRIEND_pub",)
    assert observed_ref not in {row["key_ref"] for row in loaded.keys}

    bus.use(iface)
    second = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert second.exit_code == 0
    assert json.loads(second.stdout)["admin_keys"][0]["refs"] == ["FRIEND_pub"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ("FRIEND_pub",)


def test_adopt_zero_admin_keys_is_clean(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01", short_name="MT01", long_name="Meshtastic MT01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["admin_keys"] == []
    assert document["warnings"] == []

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert NodeRecord.from_row(loaded.nodes[0]).authorized_admin_keys == ()


def test_adopt_single_unregistered_admin_key_reports_one_present_zero_recognized(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    stray_kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(stray_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert len(document["admin_keys"]) == 1
    assert document["admin_keys"][0]["refs"] == []

    # Still auto-registered under a synthetic ref, even without --show-admin-keys.
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    adopted = NodeRecord.from_row(loaded.nodes[0])
    assert adopted.authorized_admin_keys == (observed_key_ref(stray_kp.public),)
    assert adopted.unregistered_admin_keys == ()


def test_adopt_then_enroll_round_trip(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    adopted = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert adopted.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    observed = NodeRecord.from_row(loaded.nodes[0])
    assert observed.management is ManagementMode.OBSERVED

    enrolled = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--enroll"], env)
    assert enrolled.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    managed = NodeRecord.from_row(loaded.nodes[0])
    assert managed.management is ManagementMode.TEMPLATE


def test_status_surfaces_management_across_a_mixed_fleet(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    template_node = NodeRecord(
        node_id="aaaa0001",
        management=ManagementMode.TEMPLATE,
        short_name="MT01",
        long_name="Meshtastic MT01",
    )
    observed_node = NodeRecord(
        node_id="bbbb0002",
        management=ManagementMode.OBSERVED,
        short_name="OB02",
        long_name="Observed Node 02",
    )
    seed_db(nodes=[template_node, observed_node])

    bus.use(FakeMeshInterface("cccc0003"))
    adopted = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert adopted.exit_code == 0
    enrolled = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--enroll"], env)
    assert enrolled.exit_code == 0

    with mock_sources(nodes={}):
        status_doc = json.loads(invoke(runner, ["status", "--json"], env).stdout)
    by_id = {n["node_id"]: n for n in status_doc["nodes"]}
    assert set(by_id) == {"aaaa0001", "bbbb0002", "cccc0003"}
    for node in by_id.values():
        assert set(node["database"]) == {
            "short_name",
            "long_name",
            "role",
            "region",
            "management",
        }
    assert by_id["aaaa0001"]["database"]["management"] == "template"
    assert by_id["bbbb0002"]["database"]["management"] == "observed"
    assert by_id["cccc0003"]["database"]["management"] == "template"

    with mock_sources(nodes={}):
        table = invoke(runner, ["status"], env)
    assert table.exit_code == 0
    assert "observed" in table.stdout

    verify_result = invoke(runner, ["db", "verify", "--json"], env)
    verify_doc = json.loads(verify_result.stdout)
    assert verify_result.exit_code == 0, verify_doc["problems"]
    assert verify_doc["node_count"] == 3
    assert "nodes" not in verify_doc


def test_adopt_json_output_reports_the_expected_fields(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["node_id"] == "deadbe01"
    assert document["existing_management"] is None
    assert document["ble_pin_captured"] is False
    assert isinstance(document["warnings"], list)


def test_adopt_warns_on_a_duplicate_name_and_folds_it_into_json_warnings(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="cafe0001", short_name="AB01", long_name="Adopted Node 01")])
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    text_result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert text_result.exit_code == 0
    assert "short_name 'AB01'" in text_result.stderr
    assert "long_name 'Adopted Node 01'" in text_result.stderr
    assert "cafe0001" in text_result.stderr

    json_result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert json_result.exit_code == 0
    document = json.loads(json_result.stdout)
    assert any("short_name 'AB01'" in warning for warning in document["warnings"])
    assert any("long_name 'Adopted Node 01'" in warning for warning in document["warnings"])


def test_adopt_does_not_warn_when_the_live_key_is_already_a_known_registered_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A key already recognized via any ref must never trip the clone warning.

    Regression test: an earlier version compared a device's live admin
    keys against every other node's *registered* material too, which is
    provably always redundant with -- never a signal beyond -- this same
    device's own already-resolved ``preferred_ref`` (both are looked up
    in the identical ``public_keys`` map), so it did nothing but false-
    alarm on the standard ``template.admin_nodes``-shared-admin-key
    fleet pattern: the operator's own admin key, authorized on many
    nodes by design, would trip "CVE-2025-52464 vendor key-cloning" on
    nearly every adopt after the first. Here, ``shared_kp`` is already
    registered as ``OTHER_pub`` and authorized on ``cafe0001`` -- exactly
    that pattern -- and reporting it live on a second, newly-adopted
    device must be silent.
    """
    shared_kp = keypair_factory()
    pub, priv = KeyRecord.for_keypair("OTHER", shared_kp, origin=KeyOrigin.IMPORTED)
    seed_db(
        nodes=[NodeRecord(node_id="cafe0001", authorized_admin_keys=("OTHER_pub",))],
        keys=[pub, priv],
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(shared_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert not any("CVE-2025-52464" in w for w in document["warnings"])


def test_adopt_warns_on_a_shared_admin_key_already_filed_as_observed(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """The second tier: the other node's copy was already auto-registered.

    Once the first shared device has been adopted under the new
    auto-registration behavior, its copy no longer sits on
    ``unregistered_admin_keys`` at all -- it is ``authorized_admin_keys``
    under a synthetic ``observed-*`` ref. This is the scenario that tier
    exists to keep catching, as an informational note that the key still
    needs `mesh admin import`, not a CVE-2025-52464 clone alarm.
    """
    shared_kp = keypair_factory()
    observed_ref = observed_key_ref(shared_kp.public)
    seed_db(
        nodes=[NodeRecord(node_id="cafe0001", authorized_admin_keys=(observed_ref,))],
        keys=[
            KeyRecord.from_material(
                observed_ref.removesuffix("_pub"),
                KeyType.ADMIN_PUBLIC,
                shared_kp.public,
                origin=KeyOrigin.IMPORTED,
            )
        ],
    )
    bus.use(FakeMeshInterface("deadbe01")).localNode.localConfig.security.admin_key.append(
        shared_kp.public
    )

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert any("cafe0001" in w and "mesh admin import" in w for w in document["warnings"])
    assert not any("CVE" in w for w in document["warnings"])


def test_adopt_warns_on_a_shared_admin_key_previously_observed_unregistered(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Exact-material comparison against another node's never-imported observed key.

    The scenario the fix exists for: two devices report the same admin
    key, neither ever registered in the Keys sheet -- the normal
    shared-admin-key shape, reported as a WARNING nudging the operator to
    import it, not a CVE-2025-52464 clone alarm.
    """
    shared_kp = keypair_factory()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="cafe0001",
                unregistered_admin_keys=(encode_key(shared_kp.public),),
            )
        ]
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(shared_kp.public)

    # Human-text mode: the sibling duplicate-name warning is covered in this
    # mode elsewhere, but this loop (cli/adopt.py's `for warning in
    # duplicate_admin_key_warnings: ctx.warn(warning)`) previously had no
    # coverage outside --json -- a no-op regression there would only ever
    # have been caught by the JSON-mode assertion below.
    text_result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert text_result.exit_code == 0
    assert "mesh admin import" in text_result.stderr
    assert "cafe0001" in text_result.stderr
    assert "CVE" not in text_result.stderr

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert any("cafe0001" in w and "mesh admin import" in w for w in document["warnings"])

    # The same share must also be visible to the fleet-wide audit, not only
    # to the one adopt run that happened to see the second device.
    verify_result = invoke(runner, ["db", "verify", "--json"], env)
    verify_doc = json.loads(verify_result.stdout)
    assert verify_result.exit_code == int(ExitCode.OK)
    unimported = [p for p in verify_doc["problems"] if p["kind"] == "unimported_admin_key"]
    assert len(unimported) == 1
    assert unimported[0]["severity"] == "warning"
    assert unimported[0]["ref"] == "cafe0001,deadbe01"
    assert "CVE" not in unimported[0]["message"]


def test_duplicate_admin_key_check_examines_every_live_admin_key_not_just_the_first(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A device reporting more than one live admin key must have all of them checked.

    Regression test: every other shared-admin-key test in this module
    gives the live device exactly one ``admin_key``, so a regression
    narrowing ``_shared_unimported_admin_key_notes``'s ``for key in
    admin_keys:`` loop to only the device's first live key -- plausible,
    since real devices can and do report more than one -- would go
    undetected. Here the clean key is reported first and the shared one
    second, so only a genuine full scan catches it.
    """
    clean_kp = keypair_factory()
    shared_kp = keypair_factory()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="cafe0001",
                unregistered_admin_keys=(encode_key(shared_kp.public),),
            )
        ]
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(clean_kp.public)
    iface.localNode.localConfig.security.admin_key.append(shared_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert any("cafe0001" in w and "mesh admin import" in w for w in document["warnings"])


def test_adopt_does_not_warn_about_two_nodes_both_reporting_an_empty_name(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    """Two genuinely unnamed devices must never trip a false empty-string collision.

    Regression test for the ``short_name and ...`` / ``long_name and ...``
    empty-string guards in ``_duplicate_name_warnings``: without them,
    every adopt after the first device with a blank name would spuriously
    warn that ``''`` is "already used" by the earlier one -- the same
    false-positive failure mode this module's admin-key check exists to
    avoid for a different comparison, here structurally untested since no
    existing test pairs two blank-named nodes.
    """
    seed_db(nodes=[NodeRecord(node_id="cafe0001", short_name="", long_name="")])
    bus.use(FakeMeshInterface("deadbe01", short_name="", long_name=""))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    warnings = json.loads(result.stdout)["warnings"]
    assert not any("already used by node" in w for w in warnings)


def test_duplicate_name_check_skips_self_without_skipping_the_nodes_after_it(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    """Re-adopting must skip only the node's own row, never stop the scan there.

    ``NodeRepository.all()`` returns rows in sheet order, so the live
    node's own record (recorded by a previous adopt) is seeded *before*
    the genuinely colliding node. A ``continue``-to-``break`` regression
    in the self-skip guard would stop the cross-fleet check at the live
    node's own row and silently miss ``cafe0001`` entirely.
    """
    seed_db(
        nodes=[
            NodeRecord(node_id="aaaa0001", short_name="ZZ01", long_name="Zeroth Node"),
            NodeRecord(
                node_id="deadbe01",
                management=ManagementMode.OBSERVED,
                short_name="AB01",
                long_name="Adopted Node 01",
            ),
            NodeRecord(node_id="cafe0001", short_name="AB01", long_name="Adopted Node 01"),
        ]
    )
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    warnings = json.loads(result.stdout)["warnings"]
    assert any("short_name 'AB01'" in w and "cafe0001" in w for w in warnings)
    assert any("long_name 'Adopted Node 01'" in w and "cafe0001" in w for w in warnings)
    assert not any("deadbe01" in w for w in warnings)


def test_duplicate_admin_key_check_skips_self_without_skipping_the_nodes_after_it(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """The shared-admin-key cross-fleet check must survive the live node's own row.

    Same ordering trap as the name check: the live node's own record sits
    in the middle of the sheet, so a ``continue``-to-``break`` regression
    in the self-skip guard would never reach the shared key on
    ``cafe0001``.
    """
    shared_kp = keypair_factory()
    unrelated_kp = keypair_factory()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="aaaa0001",
                unregistered_admin_keys=(encode_key(unrelated_kp.public),),
            ),
            NodeRecord(
                node_id="deadbe01",
                management=ManagementMode.OBSERVED,
                unregistered_admin_keys=(encode_key(shared_kp.public),),
            ),
            NodeRecord(
                node_id="cafe0001",
                unregistered_admin_keys=(encode_key(shared_kp.public),),
            ),
        ]
    )
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(shared_kp.public)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0
    warnings = json.loads(result.stdout)["warnings"]
    share_warnings = [w for w in warnings if "mesh admin import" in w]
    assert len(share_warnings) == 1
    assert "cafe0001" in share_warnings[0]
    assert not any("deadbe01" in w for w in share_warnings)


def test_adopt_does_not_warn_about_its_own_previously_persisted_fingerprint(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A re-adopt of the same node must never flag itself as a duplicate."""
    kp = keypair_factory()
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.admin_key.append(kp.public)

    first = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert first.exit_code == 0
    assert not any("CVE-2025-52464" in w for w in json.loads(first.stdout)["warnings"])

    bus.use(iface)
    second = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
    assert second.exit_code == 0
    assert not any("CVE-2025-52464" in w for w in json.loads(second.stdout)["warnings"])


def test_declining_the_adopt_prompt_writes_nothing(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    iface = bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["--interactive", "adopt", "--port", "/dev/ttyFAKE0"], env, input="n\n")

    assert result.exit_code == int(ExitCode.INTERRUPTED)
    assert "Aborted." in result.stderr
    assert iface.localNode.written_sections == []
    assert db_fingerprint(db_path) == before


def test_adopt_prints_connect_progress_over_ble(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """`mesh adopt --ble-scan` always announces the connect, with no flag needed.

    It used to print nothing between device selection and its report -- the
    whole connect was silent (see the ``-v``/progress CHANGELOG entry).
    """
    bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))

    result = invoke(runner, ["adopt", "--ble-address", "AA:BB:CC:DD:EE:FF", "--yes"], env)

    assert result.exit_code == 0
    assert "Connecting over ble AA:BB:CC:DD:EE:FF..." in result.stderr
    assert "Connected. Reading live config..." in result.stderr
    # The heartbeat itself only ticks after its interval elapses, which the
    # fake, instantaneous `connect()` never reaches -- covered directly in
    # tests/unit/test_progress.py.


def test_adopt_debug_logs_are_hidden_by_default_and_shown_with_verbose(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """This project's own DEBUG logs stay out of the default run and appear under `-vv`.

    Uses :func:`~meshprovision.provisioning.detect.read_live_config`'s own
    debug log rather than a connection-backend one: the `bus` fixture
    monkeypatches ``connect()`` at the class level (replacing it outright,
    to inject :class:`FakeMeshInterface` without a real transport), so a
    debug log *inside* the real ``connect()`` implementation would never
    fire in this harness -- ``read_live_config`` runs unmodified against
    the fake interface, same as the real connect path.

    ``-vv`` rather than a single ``-v``: the ladder is staged so ``-v``
    alone only reaches ``INFO`` (see
    :func:`~meshprovision.cli.common.resolve_log_level`); ``DEBUG``
    needs a second ``-v``.
    """
    bus.use(FakeMeshInterface("deadbe01"))
    needle = "Read live config from !deadbe01"

    quiet = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert quiet.exit_code == 0
    assert needle not in quiet.stderr

    bus.use(FakeMeshInterface("deadbe02", short_name="AB02"))
    verbose = invoke(runner, ["-vv", "adopt", "--port", "/dev/ttyFAKE1", "--yes"], env)
    assert verbose.exit_code == 0
    assert "Read live config from !deadbe02" in verbose.stderr


@dataclass(frozen=True)
class _FleetSpec:
    node_id: str
    short_name: str
    long_name: str
    firmware: str
    admin_key: str | None
    fits_pattern: bool


_FLEET_SPECS: tuple[_FleetSpec, ...] = (
    _FleetSpec("10000001", "MT01", "Meshtastic MT01", "2.7.11", None, True),
    _FleetSpec("10000002", "MT02", "Meshtastic MT02", "2.7.11", "a", True),
    _FleetSpec("10000003", "RTR3", "East Ridge Repeater", "2.7.11", "a", False),
    _FleetSpec("10000004", "MT04", "Meshtastic MT04", "2.4.0", None, True),
    _FleetSpec("10000005", "GW05", "Garage Gateway", "2.5.0", "b", False),
    # Every unregistered admin key in this fleet is distinct on purpose:
    # a key shared by two nodes and imported for neither would trip the
    # `unimported_admin_key` WARNING `mesh db verify` now reports, which
    # this test asserts the fleet is free of.
    _FleetSpec("10000006", "MT06", "Meshtastic MT06", "2.6.10", "d", True),
    _FleetSpec("20000abc", "HM", "", "2.6.11", None, False),
    _FleetSpec("20000def", "MT08", "Meshtastic MT08", "2.7.5", "a", True),
    _FleetSpec("30001111", "NODE9", "Backyard Sensor Node", "2.3.11", "c", False),
    _FleetSpec("30002222", "MT10", "Meshtastic MT10", "2.7.11", "a", True),
    _FleetSpec("4a5b6c7d", "EDGE", "Edge Case Node", "2.6.9", None, False),
    _FleetSpec("deadffff", "MT12", "Meshtastic MT12", "2.7.11", None, True),
)


def test_fleet_adopt_heterogeneous_batch(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    kp_a = keypair_factory()
    kp_b = keypair_factory()
    kp_c = keypair_factory()
    kp_d = keypair_factory()
    key_lookup = {"a": kp_a.public, "b": kp_b.public, "c": kp_c.public, "d": kp_d.public}

    pub_a, priv_a = KeyRecord.for_keypair("FRIENDA", kp_a, origin=KeyOrigin.IMPORTED)
    seed_db(nodes=[], keys=[pub_a, priv_a])

    fleet_results: dict[str, dict[str, object]] = {}
    for spec in _FLEET_SPECS:
        iface = FakeMeshInterface(
            spec.node_id,
            short_name=spec.short_name,
            long_name=spec.long_name,
            firmware_version=spec.firmware,
        )
        if spec.admin_key is not None:
            iface.localNode.localConfig.security.admin_key.append(key_lookup[spec.admin_key])
        bus.use(iface)
        result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
        assert result.exit_code == 0
        fleet_results[spec.node_id] = json.loads(result.stdout)

    for spec in _FLEET_SPECS:
        assert fleet_results[spec.node_id]["node_id"] == spec.node_id
        assert fleet_results[spec.node_id]["existing_management"] is None

    for spec in _FLEET_SPECS:
        has_warning = any(
            "does not match the configured pattern" in w
            for w in fleet_results[spec.node_id]["warnings"]
        )
        assert has_warning == (not spec.fits_pattern)

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert set(nodes) == {spec.node_id for spec in _FLEET_SPECS}
    assert len(nodes) == len(_FLEET_SPECS)
    assert all(n.management is ManagementMode.OBSERVED for n in nodes.values())
    for spec in _FLEET_SPECS:
        assert nodes[spec.node_id].short_name == spec.short_name
        assert nodes[spec.node_id].long_name == spec.long_name
        assert nodes[spec.node_id].firmware_version == spec.firmware

    for spec in _FLEET_SPECS:
        if spec.admin_key is None:
            assert nodes[spec.node_id].authorized_admin_keys == ()
        elif spec.admin_key == "a":
            # Already registered under FRIENDA_pub -- resolved directly,
            # never given a synthetic ref.
            assert nodes[spec.node_id].authorized_admin_keys == ("FRIENDA_pub",)
        else:
            # b/c/d are each unregistered and used by exactly one node --
            # auto-registered under their own content-addressed ref.
            assert nodes[spec.node_id].authorized_admin_keys == (
                observed_key_ref(key_lookup[spec.admin_key]),
            )
        assert nodes[spec.node_id].unregistered_admin_keys == ()

    verify_result = invoke(runner, ["db", "verify", "--json"], env)
    verify_doc = json.loads(verify_result.stdout)
    assert verify_result.exit_code == 0, verify_doc["problems"]
    assert verify_doc["node_count"] == 12
    # FRIENDA pub+priv, plus one freshly minted observed-* row each for
    # the three distinct, single-node, never-imported keys (b, c, d).
    assert verify_doc["key_count"] == 5
    assert verify_doc["problems"] == []

    before = db_fingerprint(Path(env["MESHPROVISION_DB_PATH"]))
    with mock_sources(nodes={}):
        status_result = invoke(runner, ["status", "--json"], env)
    assert status_result.exit_code == 0
    assert db_fingerprint(Path(env["MESHPROVISION_DB_PATH"])) == before
    assert len(json.loads(status_result.stdout)["nodes"]) == 12

    assert fleet_results["10000005"]["firmware_vulnerable"] is True
    assert fleet_results["10000006"]["firmware_vulnerable"] is True
    assert fleet_results["10000001"]["firmware_vulnerable"] is False
    assert fleet_results["10000004"]["firmware_vulnerable"] is False


def test_adopt_batch_flags_only_the_vulnerable_firmware_nodes(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    specs = [
        ("aaaa0001", "2.4.9"),
        ("bbbb0002", "2.5.0"),
        ("cccc0003", "2.6.10"),
        ("dddd0004", "2.6.11"),
        ("eeee0005", "2.7.11"),
    ]
    reports: dict[str, dict[str, object]] = {}
    for node_id, firmware in specs:
        bus.use(FakeMeshInterface(node_id, firmware_version=firmware))
        result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)
        assert result.exit_code == 0
        reports[node_id] = json.loads(result.stdout)

    assert reports["aaaa0001"]["firmware_vulnerable"] is False
    assert reports["bbbb0002"]["firmware_vulnerable"] is True
    assert reports["cccc0003"]["firmware_vulnerable"] is True
    assert reports["dddd0004"]["firmware_vulnerable"] is False
    assert reports["eeee0005"]["firmware_vulnerable"] is False
    assert reports["aaaa0001"]["firmware_vulnerable"] != reports["bbbb0002"]["firmware_vulnerable"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert set(nodes) == {n for n, _ in specs}
    assert all(n.management is ManagementMode.OBSERVED for n in nodes.values())


def test_adopt_survives_a_hung_ble_close(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung ``iface.close()`` must never swallow an already-obtained result.

    Reproduces, at the CLI level, a confirmed reentrancy bug in meshtastic
    2.7.11's ``BLEInterface``: its ``disconnected_callback`` re-invokes
    ``close()`` on disconnect, and that second call can hang forever on a
    GATT write against an already-torn-down client (see
    :data:`meshprovision.provisioning.connection.DEFAULT_CLOSE_TIMEOUT`).
    ``mesh adopt`` had already obtained everything it needs
    (``read_live_config`` succeeds before the hang) -- a hung close must
    not prevent it from reporting that result and exiting.

    The fake's ``close()`` blocks on a never-set ``threading.Event``
    rather than ``time.sleep`` -- the root ``tests/conftest.py``
    monkeypatches ``time.sleep`` to a no-op for every test, which would
    make a ``time.sleep``-based fake return instantly instead of hanging.
    The real default timeout (``DEFAULT_CLOSE_TIMEOUT``) is patched down
    for this test only, so it runs at unit-test speed rather than waiting
    out the real multi-second bound.
    """
    from meshprovision.provisioning import connection as connection_module

    real_close_interface = connection_module.close_interface

    def _fast_close_interface(iface: object, *, timeout: float = 0.05) -> None:
        real_close_interface(iface, timeout=timeout)  # type: ignore[arg-type]

    monkeypatch.setattr(connection_module, "close_interface", _fast_close_interface)

    iface = bus.use(FakeMeshInterface("deadbe01", short_name="AB01", long_name="Adopted Node 01"))
    monkeypatch.setattr(iface, "close", threading.Event().wait)

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0
    assert "deadbe01" in result.stderr
    assert "did not complete" in result.stderr

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    assert nodes[0].node_id == "deadbe01"


# --- mesh adopt --from-backup ---------------------------------------------------


def _write_profile_cfg(
    path: Path,
    *,
    long_name: str = "Meshtastic MT01",
    short_name: str = "MT01",
    channel_url: str = "",
    public_key: bytes = b"",
    private_key: bytes = b"",
) -> Path:
    """Write a synthetic ``.cfg`` ``DeviceProfile`` backup to ``path``."""
    profile = clientonly_pb2.DeviceProfile()
    profile.long_name = long_name
    profile.short_name = short_name
    if channel_url:
        profile.channel_url = channel_url
    profile.config.lora.region = config_pb2.Config.LoRaConfig.EU_868
    profile.config.device.role = config_pb2.Config.DeviceConfig.CLIENT
    if public_key:
        profile.config.security.public_key = public_key
    if private_key:
        profile.config.security.private_key = private_key
    path.write_bytes(profile.SerializeToString())
    return path


def _write_nodedb_json(
    path: Path, *, num: int, node_id: str, long_name: str, short_name: str, public_key: bytes = b""
) -> Path:
    """Write a synthetic node-db JSON export to ``path``."""
    entry: dict[str, object] = {
        "num": num,
        "id": node_id,
        "longName": long_name,
        "shortName": short_name,
        "hwModel": "TBEAM",
        "role": "CLIENT",
        "metadata": {"firmwareVersion": "2.6.11"},
    }
    if public_key:
        entry["publicKey"] = base64.b64encode(public_key).decode()
    payload = {
        "schemaVersion": 1,
        "exportedAt": "2026-01-01T00:00:00Z",
        "myNodeNum": num,
        "nodes": [entry],
    }
    path.write_text(json.dumps(payload))
    return path


def test_from_backup_never_touches_any_connection_backend(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--yes"],
        env,
    )

    assert result.exit_code == 0
    assert bus.connections == []


def test_from_backup_persists_an_observed_record(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    cfg = _write_profile_cfg(
        tmp_path / "profile.cfg", public_key=kp.public, private_key=kp.private.reveal()
    )

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--yes"],
        env,
    )

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.node_id == "a0cb5cc4"
    assert node.management is ManagementMode.OBSERVED
    assert node.short_name == "MT01"
    assert node.long_name == "Meshtastic MT01"
    assert node.region == "EU_868"
    assert node.role == "CLIENT"

    keys = {row["key_ref"]: row for row in loaded.keys}
    assert "a0cb5cc4_pub" in keys
    assert "a0cb5cc4_priv" in keys


def test_from_backup_dry_run_writes_nothing(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--dry-run"],
        env,
    )

    assert result.exit_code == 0
    assert db_fingerprint(db_path) == before


def test_from_backup_dry_run_describes_every_key_row_a_real_run_would_write(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    """Regression test for Round 35's backup-adoption review, Finding 4.

    --dry-run's help text promises to "print the report without writing
    to the database" -- but the preview mentioned none of the up to
    three Keys-sheet rows (<id>_pub, <id>_priv, <id>_psk) a real
    --from-backup run writes, including the node's own private key. It
    must now say what will be recorded, in both human and --json output,
    before any write happens.
    """
    kp = keypair_factory()
    psk = bytes(range(32))
    channel_set = apponly_pb2.ChannelSet()
    channel_set.settings.add(psk=psk, name="Primary")
    frag = base64.urlsafe_b64encode(channel_set.SerializeToString()).decode().rstrip("=")
    cfg = _write_profile_cfg(
        tmp_path / "profile.cfg",
        channel_url=f"https://meshtastic.org/e/#{frag}",
        public_key=kp.public,
        private_key=kp.private.reveal(),
    )
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--dry-run"],
        env,
    )

    assert result.exit_code == 0
    assert db_fingerprint(db_path) == before
    assert "own public key will be recorded as a0cb5cc4_pub" in result.stderr
    assert "own private key will be recorded as a0cb5cc4_priv" in result.stderr
    assert "channel 'Primary' PSK will be recorded as a0cb5cc4_psk" in result.stderr

    json_result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(cfg),
            "--node-id",
            "!a0cb5cc4",
            "--no-lookup",
            "--dry-run",
            "--json",
        ],
        env,
    )
    payload = json.loads(json_result.stdout)
    assert payload["own_public_key_captured"] is True
    assert payload["own_private_key_captured"] is True
    assert payload["channel_name_to_record"] == "Primary"


def test_from_backup_conflicts_with_a_transport_flag(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")

    result = invoke(runner, ["adopt", "--from-backup", str(cfg), "--port", "/dev/ttyFAKE0"], env)

    assert result.exit_code != 0
    assert "--from-backup cannot be combined" in result.stderr


def test_node_id_without_from_backup_is_rejected(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["adopt", "--node-id", "!a0cb5cc4"], env)

    assert result.exit_code != 0
    assert "--node-id only applies together with --from-backup" in result.stderr


def test_from_backup_without_any_identity_evidence_refuses(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg", long_name="Meshtastic Nobody Knows")

    with mock_sources():  # no source has ever heard of this node
        result = invoke(runner, ["adopt", "--from-backup", str(cfg)], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "Could not determine this node's id" in result.stderr


def test_from_backup_suggests_a_node_id_via_loranet_long_name_match(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg", long_name="Meshtastic Rooftop")

    with mock_sources(nodes={"a0cb5cc4": {"longName": "Meshtastic Rooftop"}}):
        result = invoke(runner, ["adopt", "--from-backup", str(cfg)], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "!a0cb5cc4" in result.stderr
    assert "--node-id !a0cb5cc4" in result.stderr


def test_from_backup_no_lookup_skips_the_suggestion_and_never_calls_out(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg", long_name="Meshtastic Rooftop")

    with mock_sources(nodes={"deadbeef": {"longName": "Meshtastic Rooftop"}}) as router:
        result = invoke(runner, ["adopt", "--from-backup", str(cfg), "--no-lookup"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "loranet" not in result.stderr
    assert router.calls.call_count == 0


def test_from_backup_public_key_match_resolves_node_id(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    tmp_path: Path,
    keypair_factory: Callable[[], KeyPair],
) -> None:
    kp = keypair_factory()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="a0cb5cc4",
                short_name="OLD1",
                long_name="Old Node",
                management=ManagementMode.OBSERVED,
            )
        ],
        keys=[
            KeyRecord.from_material(
                "a0cb5cc4", KeyType.ADMIN_PUBLIC, kp.public, origin=KeyOrigin.CAPTURED
            )
        ],
    )
    cfg = _write_profile_cfg(tmp_path / "profile.cfg", public_key=kp.public)

    result = invoke(runner, ["adopt", "--from-backup", str(cfg), "--no-lookup", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    assert nodes[0].node_id == "a0cb5cc4"


def test_from_backup_paired_nodedb_resolves_via_my_node_num(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xA0CB5CC4,
        node_id="!a0cb5cc4",
        long_name="Meshtastic MT01",
        short_name="MT01",
    )

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--from-backup", str(nodedb), "--yes"],
        env,
    )

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.node_id == "a0cb5cc4"
    assert node.hw_model == "TBEAM"
    assert node.firmware_version == "2.6.11"


def test_from_backup_nodedb_only_does_not_fabricate_region(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    """Regression test for Round 35's backup-adoption review, Finding 1.

    A node-db-only adopt (no paired .cfg/.yaml) builds its LiveConfig
    from a bare protobuf LocalConfig with no data behind it -- persisting
    "region" from that would silently record the firmware default
    ("UNSET") as though it were a genuine observation and, on a re-adopt,
    would have overwritten a previously-recorded correct region.
    role is a genuine NodeDbEntry field, and its recognized value
    ("CLIENT" here) IS a real observation, so it is correctly preserved.
    """
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xA0CB5CC4,
        node_id="!a0cb5cc4",
        long_name="Meshtastic MT01",
        short_name="MT01",
    )

    result = invoke(runner, ["adopt", "--from-backup", str(nodedb), "--no-lookup", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    node = nodes[0]
    assert node.hw_model == "TBEAM"
    assert node.role == "CLIENT"
    assert node.region == ""


def test_from_backup_conflicting_node_id_refuses_without_force(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xA0CB5CC4,
        node_id="!a0cb5cc4",
        long_name="Meshtastic MT01",
        short_name="MT01",
    )

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(cfg),
            "--from-backup",
            str(nodedb),
            "--node-id",
            "!deadbeef",
            "--no-lookup",
        ],
        env,
    )

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "Conflicting node id evidence" in result.stderr


def test_from_backup_conflicting_node_id_force_uses_precedence(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xA0CB5CC4,
        node_id="!a0cb5cc4",
        long_name="Meshtastic MT01",
        short_name="MT01",
    )

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(cfg),
            "--from-backup",
            str(nodedb),
            "--node-id",
            "!deadbeef",
            "--no-lookup",
            "--force",
            "--yes",
        ],
        env,
    )

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert nodes[0].node_id == "deadbeef"


def test_from_backup_force_does_not_mis_file_a_different_nodes_data_or_key(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    """Regression test for Round 35's backup-adoption review, Finding 3.

    A node-db export describes whichever node the phone was connected to
    when it was taken. Forcing a *different* --node-id through a
    myNodeNum conflict must not carry that export's names/hw_model/
    public key onto the forced id -- most importantly not its public
    key, since a mis-filed <forced_id>_pub row would silently redirect
    every future backup adopt of the key's real owner (resolve_node_id's
    own public-key tier reads exactly that row).
    """
    other_node_kp = keypair_factory()
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xAAAA1111,
        node_id="!aaaa1111",
        long_name="Node A",
        short_name="NodA",
        public_key=other_node_kp.public,
    )

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(nodedb),
            "--node-id",
            "!bbbb2222",
            "--no-lookup",
            "--force",
            "--yes",
        ],
        env,
    )

    assert result.exit_code == 0
    assert "describes a different node" in result.stderr
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert set(nodes) == {"bbbb2222"}
    assert nodes["bbbb2222"].long_name != "Node A"
    assert nodes["bbbb2222"].hw_model == ""
    key_material = {row["key_ref"]: row["key_value"] for row in loaded.keys}
    assert "bbbb2222_pub" not in key_material

    # The real owner of that key must still resolve to its own id, not the
    # id it was mistakenly forced onto above.
    second_nodedb = _write_nodedb_json(
        tmp_path / "nodedb2.json",
        num=0xAAAA1111,
        node_id="!aaaa1111",
        long_name="Node A",
        short_name="NodA",
        public_key=other_node_kp.public,
    )
    second_result = invoke(
        runner, ["adopt", "--from-backup", str(second_nodedb), "--no-lookup", "--yes"], env
    )
    assert second_result.exit_code == 0
    reloaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    reloaded_nodes = {row["node_id"] for row in reloaded.nodes}
    assert reloaded_nodes == {"bbbb2222", "aaaa1111"}


def test_from_backup_records_channel_psk(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    psk = bytes(range(32))
    profile = clientonly_pb2.DeviceProfile()
    profile.long_name = "Meshtastic MT01"
    profile.short_name = "MT01"
    channel_set = apponly_pb2.ChannelSet()
    channel_set.settings.add(psk=psk, name="Primary")
    frag = base64.urlsafe_b64encode(channel_set.SerializeToString()).decode().rstrip("=")
    profile.channel_url = f"https://meshtastic.org/e/#{frag}"
    profile.config.lora.region = config_pb2.Config.LoRaConfig.EU_868
    cfg_path = tmp_path / "profile.cfg"
    cfg_path.write_bytes(profile.SerializeToString())

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg_path), "--node-id", "!a0cb5cc4", "--no-lookup", "--yes"],
        env,
    )

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys = {row["key_ref"]: row for row in loaded.keys}
    assert "a0cb5cc4_psk" in keys
    assert encode_key(psk) == keys["a0cb5cc4_psk"]["key_value"]


def test_from_backup_no_channel_psk_suppresses_the_write(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    psk = bytes(range(32))
    profile = clientonly_pb2.DeviceProfile()
    profile.long_name = "Meshtastic MT01"
    profile.short_name = "MT01"
    channel_set = apponly_pb2.ChannelSet()
    channel_set.settings.add(psk=psk, name="Primary")
    frag = base64.urlsafe_b64encode(channel_set.SerializeToString()).decode().rstrip("=")
    profile.channel_url = f"https://meshtastic.org/e/#{frag}"
    profile.config.lora.region = config_pb2.Config.LoRaConfig.EU_868
    cfg_path = tmp_path / "profile.cfg"
    cfg_path.write_bytes(profile.SerializeToString())

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(cfg_path),
            "--node-id",
            "!a0cb5cc4",
            "--no-lookup",
            "--no-channel-psk",
            "--yes",
        ],
        env,
    )

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys = {row["key_ref"] for row in loaded.keys}
    assert "a0cb5cc4_psk" not in keys


def test_from_backup_non_aes256_psk_is_skipped_with_a_warning(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    """A 1-byte "default preset" PSK cannot round-trip through the Keys sheet."""
    cfg = _write_profile_cfg(
        tmp_path / "profile.cfg", channel_url="https://meshtastic.org/e/#CgMSAQE"
    )

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--yes"],
        env,
    )

    assert result.exit_code == 0
    # rich wraps stderr at the terminal width, which can land mid-phrase --
    # collapse whitespace before matching so the assertion is wrap-width-safe.
    normalized_stderr = " ".join(result.stderr.split())
    assert "channel_psk not recorded" in normalized_stderr
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    keys = {row["key_ref"] for row in loaded.keys}
    assert "a0cb5cc4_psk" not in keys


def test_from_backup_flags_a_mismatched_own_keypair(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(
        tmp_path / "profile.cfg", public_key=bytes(range(32)), private_key=bytes(range(32, 64))
    )

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--json"],
        env,
    )

    payload = json.loads(result.stdout)
    assert any("weak-key audit" in warning for warning in payload["warnings"])
    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_adopt_flags_a_mismatched_own_keypair_from_a_live_device(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """A live device's own keypair is audited too, not just a --from-backup one."""
    iface = bus.use(FakeMeshInterface("deadbe01"))
    iface.localNode.localConfig.security.public_key = bytes(range(32))
    iface.localNode.localConfig.security.private_key = bytes(range(32, 64))

    result = invoke(runner, ["adopt", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    payload = json.loads(result.stdout)
    assert any("weak-key audit" in warning for warning in payload["warnings"])
    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_from_backup_json_output_never_leaks_key_material(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    kp = keypair_factory()
    cfg = _write_profile_cfg(
        tmp_path / "profile.cfg",
        public_key=kp.public,
        private_key=kp.private.reveal(),
        channel_url="https://meshtastic.org/e/#CgMSAQE",
    )

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(cfg),
            "--node-id",
            "!a0cb5cc4",
            "--no-lookup",
            "--json",
            "--dry-run",
        ],
        env,
    )

    assert result.exit_code == 0
    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_from_backup_source_line_appears_in_human_output(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--dry-run"],
        env,
    )

    assert result.exit_code == 0
    assert f"source: backup: {cfg}" in result.stderr


def test_from_backup_two_profile_files_is_rejected(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg1 = _write_profile_cfg(tmp_path / "one.cfg")
    cfg2 = _write_profile_cfg(tmp_path / "two.cfg")

    result = invoke(runner, ["adopt", "--from-backup", str(cfg1), "--from-backup", str(cfg2)], env)

    assert result.exit_code != 0
    assert "two profile files" in result.stderr


def test_from_backup_unrecognized_file_format_refuses(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    garbage = tmp_path / "garbage.bin"
    garbage.write_bytes(b"\x00\x01not any recognized format at all\xff\xfe")

    result = invoke(runner, ["adopt", "--from-backup", str(garbage)], env)

    assert result.exit_code == int(ExitCode.CONFIG)
    assert "not a recognized backup format" in result.stderr


def test_from_backup_preserves_hw_model_on_re_adopt_without_nodedb(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    """Re-adopting from a .cfg-only backup must not blank a previously-recorded hw_model."""
    seed_db(
        nodes=[
            NodeRecord(
                node_id="a0cb5cc4",
                hw_model="TBEAM",
                firmware_version="2.6.11",
                management=ManagementMode.OBSERVED,
            )
        ]
    )
    cfg = _write_profile_cfg(tmp_path / "profile.cfg")

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--yes"],
        env,
    )

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    node = NodeRecord.from_row(loaded.nodes[0])
    assert node.hw_model == "TBEAM"
    assert node.firmware_version == "2.6.11"
