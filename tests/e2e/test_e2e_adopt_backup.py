"""``mesh adopt --from-backup``: an observed record built from a device backup, never a device."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from meshtastic.protobuf import apponly_pb2, clientonly_pb2, config_pb2

from meshprovision.crypto.keys import encode_key
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import ExitCode
from tests.conftest import BASE64_KEY_RE
from tests.e2e.conftest import db_fingerprint, invoke, write_profile_cfg

if TYPE_CHECKING:
    from collections.abc import Callable

    import respx
    from click.testing import CliRunner

    from meshprovision.crypto.keys import KeyPair
    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


# --- mesh adopt --from-backup ---------------------------------------------------


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
    cfg = write_profile_cfg(tmp_path / "profile.cfg")

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
    cfg = write_profile_cfg(
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
    cfg = write_profile_cfg(tmp_path / "profile.cfg")

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
    cfg = write_profile_cfg(
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


def test_from_backup_json_escapes_terminal_controls_in_the_channel_name(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    """A backup's channel name reaches ``--json`` with its C1/bidi controls escaped.

    The name comes straight from the backup file, so a crafted one could
    carry the single-byte CSI (U+009B) or a bidi override (U+202E); the
    JSON on stdout must not contain them raw, yet still decode to the
    exact name.
    """
    name = "Pri\x9bm\u202eŁódź"
    channel_set = apponly_pb2.ChannelSet()
    channel_set.settings.add(psk=bytes(range(32)), name=name)
    frag = base64.urlsafe_b64encode(channel_set.SerializeToString()).decode().rstrip("=")
    cfg = write_profile_cfg(
        tmp_path / "profile.cfg", channel_url=f"https://meshtastic.org/e/#{frag}"
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
            "--dry-run",
            "--json",
        ],
        env,
    )

    assert result.exit_code == 0
    assert "\x9b" not in result.stdout
    assert "\u202e" not in result.stdout
    assert '"channel_name_to_record": "Pri\\u009bm\\u202eŁódź"' in result.stdout
    assert json.loads(result.stdout)["channel_name_to_record"] == name


def test_from_backup_conflicts_with_a_transport_flag(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = write_profile_cfg(tmp_path / "profile.cfg")

    result = invoke(runner, ["adopt", "--from-backup", str(cfg), "--port", "/dev/ttyFAKE0"], env)

    assert result.exit_code == 2
    assert "--from-backup cannot be combined" in result.stderr


def test_node_id_without_from_backup_is_rejected(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["adopt", "--node-id", "!a0cb5cc4"], env)

    assert result.exit_code == 2
    assert "--node-id only applies together with --from-backup" in result.stderr


def test_from_backup_rejects_an_unparseable_node_id_as_a_usage_error(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = write_profile_cfg(tmp_path / "profile.cfg")
    before = db_fingerprint(Path(env["MESHPROVISION_DB_PATH"]))

    result = invoke(
        runner, ["adopt", "--from-backup", str(cfg), "--node-id", "zzz", "--no-lookup"], env
    )

    assert result.exit_code == 2
    assert "Invalid value for '--node-id': Cannot parse node id: 'zzz'" in result.stderr
    assert db_fingerprint(Path(env["MESHPROVISION_DB_PATH"])) == before


def test_from_backup_without_any_identity_evidence_refuses(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    cfg = write_profile_cfg(tmp_path / "profile.cfg", long_name="Meshtastic Nobody Knows")

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
    cfg = write_profile_cfg(tmp_path / "profile.cfg", long_name="Meshtastic Rooftop")

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
    cfg = write_profile_cfg(tmp_path / "profile.cfg", long_name="Meshtastic Rooftop")

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
    cfg = write_profile_cfg(tmp_path / "profile.cfg", public_key=kp.public)

    result = invoke(runner, ["adopt", "--from-backup", str(cfg), "--no-lookup", "--yes"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = [NodeRecord.from_row(row) for row in loaded.nodes]
    assert len(nodes) == 1
    assert nodes[0].node_id == "a0cb5cc4"


def test_from_backup_paired_nodedb_resolves_via_my_node_num(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = write_profile_cfg(tmp_path / "profile.cfg")
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
    cfg = write_profile_cfg(tmp_path / "profile.cfg")
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
    cfg = write_profile_cfg(tmp_path / "profile.cfg")
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


def test_from_backup_force_refuses_a_paired_profile_carrying_the_dropped_exports_key(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    """--force must not file a paired profile's key under the forced id when it is the export's.

    merge_backups pairs a profile only with an export it agrees with, and
    an equal public key proves both files describe the export's own node
    (myNodeNum). Dropping just the export's entry and keeping the profile
    used to write that node's key as <forced_id>_pub, so a later adopt of
    the key's real owner silently resolved to the forced id. Round 41's
    logic review, Finding 1.
    """
    node_a_kp = keypair_factory()
    cfg = write_profile_cfg(
        tmp_path / "profile.cfg",
        long_name="Node A",
        short_name="NodA",
        public_key=node_a_kp.public,
    )
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xAAAA1111,
        node_id="!aaaa1111",
        long_name="Node A",
        short_name="NodA",
        public_key=node_a_kp.public,
    )
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(cfg),
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

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "carries the same public key as the node-db export's own node !aaaa1111" in (
        result.stderr
    )
    assert "alone with --node-id !bbbb2222" in result.stderr
    assert db_fingerprint(db_path) == before


def test_from_backup_force_keeps_a_paired_profile_not_bound_to_the_export_by_key(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    """Only an equal public key binds a profile to the dropped export entry.

    A profile that matches the export by name alone (here: the export has
    no public key at all) is still adopted under the forced id, its own
    key included -- --node-id is then the only claim about which node the
    profile belongs to, as for a profile passed on its own.
    """
    profile_kp = keypair_factory()
    cfg = write_profile_cfg(
        tmp_path / "profile.cfg",
        long_name="Node A",
        short_name="NodA",
        public_key=profile_kp.public,
    )
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xAAAA1111,
        node_id="!aaaa1111",
        long_name="Node A",
        short_name="NodA",
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
    assert {row["node_id"] for row in loaded.nodes} == {"bbbb2222"}
    key_material = {row["key_ref"]: row["key_value"] for row in loaded.keys}
    assert key_material["bbbb2222_pub"] == encode_key(profile_kp.public)


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
    cfg = write_profile_cfg(
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
    cfg = write_profile_cfg(
        tmp_path / "profile.cfg", public_key=bytes(range(32)), private_key=bytes(range(32, 64))
    )

    result = invoke(
        runner,
        ["adopt", "--from-backup", str(cfg), "--node-id", "!a0cb5cc4", "--no-lookup", "--json"],
        env,
    )

    payload = json.loads(result.stdout)
    assert any("weak-key audit" in warning for warning in payload["warnings"])
    assert not BASE64_KEY_RE.search(result.stdout)
    assert not BASE64_KEY_RE.search(result.stderr)


def test_from_backup_json_output_never_leaks_key_material(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    kp = keypair_factory()
    cfg = write_profile_cfg(
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
    assert not BASE64_KEY_RE.search(result.stdout)
    assert not BASE64_KEY_RE.search(result.stderr)


def test_from_backup_source_line_appears_in_human_output(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    cfg = write_profile_cfg(tmp_path / "profile.cfg")

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
    cfg1 = write_profile_cfg(tmp_path / "one.cfg")
    cfg2 = write_profile_cfg(tmp_path / "two.cfg")

    result = invoke(runner, ["adopt", "--from-backup", str(cfg1), "--from-backup", str(cfg2)], env)

    assert result.exit_code == 2
    assert "two profile files" in result.stderr


def test_from_backup_unrecognized_file_format_refuses(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    garbage = tmp_path / "garbage.bin"
    garbage.write_bytes(b"\x00\x01not any recognized format at all\xff\xfe")

    result = invoke(runner, ["adopt", "--from-backup", str(garbage)], env)

    assert result.exit_code == int(ExitCode.CONFIG)
    assert "not a recognized backup format" in result.stderr


def _profile_cfg_with_latitude_i(latitude_i: int) -> bytes:
    """A ``.cfg`` ``DeviceProfile`` whose fixed position has ``latitude_i``."""
    profile = clientonly_pb2.DeviceProfile()
    profile.long_name = "Meshtastic MT01"
    profile.short_name = "MT01"
    profile.fixed_position.latitude_i = latitude_i
    profile.fixed_position.longitude_i = 210_000_000
    return bytes(profile.SerializeToString())


@pytest.mark.parametrize(
    ("name", "content", "field"),
    [
        (
            "nodedb.json",
            b'{"nodes": [{"num": 3735928321}], "myNodeNum": Infinity}',
            "myNodeNum",
        ),
        ("profile.cfg", _profile_cfg_with_latitude_i(2_000_000_000), "fixed_position.latitude_i"),
    ],
    ids=["nodedb_infinite_my_node_num", "cfg_latitude_out_of_range"],
)
def test_from_backup_with_an_invalid_number_refuses_cleanly(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    name: str,
    content: bytes,
    field: str,
) -> None:
    backup_file = tmp_path / name
    backup_file.write_bytes(content)
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_fingerprint(db_path)

    result = invoke(
        runner,
        [
            "adopt",
            "--from-backup",
            str(backup_file),
            "--node-id",
            "!deadbe01",
            "--no-lookup",
            "--yes",
        ],
        env,
    )

    assert result.exit_code == int(ExitCode.CONFIG)
    assert field in result.stderr
    assert "Traceback" not in result.output
    assert db_fingerprint(db_path) == before


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
    cfg = write_profile_cfg(tmp_path / "profile.cfg")

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


def test_from_backup_nodedb_with_a_lone_surrogate_name_adopts_without_it(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    """A node-db longName holding a lone surrogate is dropped with a warning, not a traceback.

    Kept, it reached NodeRecord validation when the adoption was saved and
    crashed `mesh adopt` with a pydantic ValidationError (exit code 1).
    """
    nodedb = _write_nodedb_json(
        tmp_path / "nodedb.json",
        num=0xA0CB5CC4,
        node_id="!a0cb5cc4",
        long_name="Meshtastic\ud800MT01",
        short_name="MT01",
    )

    result = invoke(runner, ["adopt", "--from-backup", str(nodedb), "--no-lookup", "--yes"], env)

    assert result.exit_code == 0
    assert "node a0cb5cc4's longName is not valid Unicode text" in result.stderr
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    node = NodeRecord.from_row(loaded.nodes[0])
    assert (node.long_name, node.short_name) == ("", "MT01")
