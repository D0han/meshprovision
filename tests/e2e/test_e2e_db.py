"""``mesh db verify``/``backup``/``restore`` (schema, cross-references, weak-key audit)."""

from __future__ import annotations

import errno
import json
import os
import shutil
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db import atomic_writer, backups, ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.locking import lock_path_for
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyOrigin
from meshprovision.errors import AtomicWriteError
from tests.conftest import WIDE_TERMINAL_COLUMNS, rezip_ods
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner, Result

pytestmark = pytest.mark.e2e


def test_db_backup_create_and_list(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = tmp_path / "custom-backups"

    result = invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir)], env)

    assert result.exit_code == 0
    backups = list(backup_dir.glob("*.ods"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == db_path.read_bytes()
    assert str(db_path) in result.stderr
    assert str(backups[0]) in result.stderr

    listed = invoke(
        runner, ["db", "backup", "--backup-dir", str(backup_dir), "--list", "--json"], env
    )
    assert listed.exit_code == 0
    document = json.loads(listed.stdout)
    assert len(document["backups"]) == 1
    assert "created_at" in document["backups"][0]
    assert document["backups"][0]["size_bytes"] > 0


def test_db_backup_retention_prunes_older_backups(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    """``--retention`` is documented but was never proven to prune via the CLI.

    ``prune_backups`` itself is unit-tested, but nothing exercised
    ``mesh db backup --retention N`` end to end. Three backups created
    with ``--retention 1`` should leave exactly one file behind, since
    each call's own prune runs after its own copy succeeds.
    """
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    backup_dir = tmp_path / "retained-backups"

    for _ in range(3):
        result = invoke(
            runner, ["db", "backup", "--backup-dir", str(backup_dir), "--retention", "1"], env
        )
        assert result.exit_code == 0

    assert len(list(backup_dir.glob("*.ods"))) == 1


def test_db_backup_list_with_no_backups_reports_none_found(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[])
    backup_dir = tmp_path / "empty-backups"

    result = invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir), "--list"], env)

    assert result.exit_code == 0
    assert "No backups found." in result.stdout


def test_db_backup_list_plain_text_shows_path_and_size(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    backup_dir = tmp_path / "custom-backups"
    invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir)], env)

    result = invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir), "--list"], env)

    assert result.exit_code == 0
    assert "bytes" in result.stdout
    assert str(backup_dir) in result.stdout


def test_db_backup_create_json_reports_source_and_backup_paths(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = tmp_path / "custom-backups"

    result = invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir), "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["source"] == str(db_path)
    assert Path(document["backup"]).exists()
    assert document["size_bytes"] > 0


def test_db_backup_missing_database_exits_four(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(env)
    env["MESHPROVISION_DB_PATH"] = str(tmp_path / "does-not-exist.ods")

    result = invoke(runner, ["db", "backup"], env)

    assert result.exit_code == 4


def test_db_restore_overwrites_the_live_database(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = tmp_path / "backups"
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="OLD1", region="EU_868")])
    invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir)], env)
    old_backup = next(backup_dir.glob("*.ods"))

    seed_db(nodes=[NodeRecord(node_id="deadbe02", short_name="NEW2", region="EU_868")])
    assert db_path.read_bytes() != old_backup.read_bytes()

    result = invoke(
        runner, ["db", "restore", str(old_backup), "--yes", "--backup-dir", str(backup_dir)], env
    )

    assert result.exit_code == 0
    assert db_path.read_bytes() == old_backup.read_bytes()
    assert str(db_path) in result.stderr
    assert str(old_backup) in result.stderr

    # The pre-restore content was itself backed up -- a restore is
    # reversible. Counted via list_backups(), not a bare "*.ods" glob:
    # the restore's own post-load verification also refreshes the
    # known-good copy here, since --backup-dir happens to coincide with
    # this database's own default-resolved backup directory.
    assert len(backups.list_backups(db_path, backup_dir=backup_dir)) == 2


def test_db_restore_json_reports_target_and_source(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = tmp_path / "backups"
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir)], env)
    backup_file = next(backup_dir.glob("*.ods"))

    result = invoke(
        runner,
        ["db", "restore", str(backup_file), "--yes", "--backup-dir", str(backup_dir), "--json"],
        env,
    )

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["target"] == str(db_path)
    assert document["restored_from"] == str(backup_file)


def test_db_restore_refuses_without_confirmation_when_non_interactive(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    """No --yes, and CliRunner's stdin is never a TTY -- must refuse, never restore silently."""
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = tmp_path / "backups"
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir)], env)
    backup_file = next(backup_dir.glob("*.ods"))
    before = db_path.read_bytes()

    result = invoke(
        runner, ["db", "restore", str(backup_file), "--backup-dir", str(backup_dir)], env
    )

    assert result.exit_code == 5
    assert db_path.read_bytes() == before


def test_db_restore_of_an_unparsable_backup_reports_a_clear_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    """A corrupt/non-ODS backup file must be refused before the live database is touched."""
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    before = db_path.read_bytes()
    bad_backup = tmp_path / "not-an-ods-file.ods"
    bad_backup.write_text("not a zip file")

    result = invoke(
        runner, ["db", "restore", str(bad_backup), "--yes", "--backup-dir", str(backup_dir)], env
    )

    assert result.exit_code == 4
    assert "nothing was restored" in result.stderr
    assert "mesh db backup --list --backup-dir" in result.stderr
    assert str(backup_dir) in result.stderr
    # Validation happens before any write: the live database is byte-identical
    # to what it was before the failed restore, and no pre-restore safety
    # backup of it was ever created.
    assert db_path.read_bytes() == before
    assert list(backup_dir.glob("*.ods")) == []


def test_db_restore_missing_backup_file_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])

    result = invoke(runner, ["db", "restore", str(tmp_path / "does-not-exist.ods"), "--yes"], env)

    assert result.exit_code == 2


# --- the known-good safety copy ---------------------------------------------------


def test_load_failure_hint_names_the_known_good_copy(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """The core remediation story: a hand-edit corruption's error points at the safety copy."""
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])

    # Any successful load refreshes the known-good copy -- db verify is
    # the documented post-hand-edit ritual, so use that one.
    first = invoke(runner, ["db", "verify"], env)
    assert first.exit_code == 0

    # Simulate a hand-edit that destroys the file (a truncated/corrupted save).
    db_path.write_bytes(b"not a zip file at all")

    second = invoke(runner, ["db", "verify"], env)

    assert second.exit_code == 4
    assert "not a readable ODF spreadsheet" in second.stderr
    assert "A known-good copy from" in second.stderr
    assert "mesh db restore --known-good" in second.stderr


def test_load_failure_with_no_known_good_copy_gets_no_extra_hint(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    """No prior successful load ever happened -- there is nothing to point at yet."""
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    db_path.write_bytes(b"not a zip file at all")

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 4
    assert "A known-good copy" not in result.stderr


def test_load_failure_permission_error_gets_permission_hint_not_restore(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """A permission error isn't corruption: no restore hint, even with a known-good copy."""
    if os.getuid() == 0:
        pytest.skip("root bypasses file permission checks")
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])

    # Refresh the known-good copy first, so one is available.
    assert invoke(runner, ["db", "verify"], env).exit_code == 0

    db_path.chmod(0o000)
    try:
        result = invoke(runner, ["db", "verify"], env)
    finally:
        db_path.chmod(0o644)

    assert result.exit_code == 4
    assert "not a readable ODF spreadsheet" not in result.stderr
    assert "permissions" in result.stderr
    assert "mesh db restore --known-good" not in result.stderr
    assert "A known-good copy" not in result.stderr


def test_db_restore_known_good_restores_it(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    good_bytes = db_path.read_bytes()

    assert invoke(runner, ["db", "verify"], env).exit_code == 0  # refreshes the known-good copy
    db_path.write_bytes(b"not a zip file at all")
    assert invoke(runner, ["db", "verify"], env).exit_code == 4

    result = invoke(runner, ["db", "restore", "--known-good", "--yes"], env)

    assert result.exit_code == 0
    assert db_path.read_bytes() == good_bytes
    assert invoke(runner, ["db", "verify"], env).exit_code == 0


def _seed_with_private_key(seed_db: Callable[..., Path]) -> tuple[Path, str]:
    """Seed one node plus its keypair; return the database path and the private key's text."""
    pub, priv = KeyRecord.for_keypair(
        "deadbe01",
        generate_keypair(),
        origin=KeyOrigin.CAPTURED,
        created_ts=datetime(2026, 1, 1, tzinfo=UTC),
    )
    path = seed_db(
        nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")],
        keys=[pub, priv],
    )
    return path, priv.key_value.get_secret_value()


def test_damaged_content_is_refused_and_known_good_restores_the_rows(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """A content.xml cut short outside mesh: refused, never printed, recoverable.

    odfpy alone loaded such a file as "Database OK" with the rows past the
    cut silently gone (printing the XML, private keys included, to
    stdout), and that load refreshed the known-good copy with the
    truncated content.
    """
    db_path, secret = _seed_with_private_key(seed_db)
    good_bytes = db_path.read_bytes()
    assert invoke(runner, ["db", "verify"], env).exit_code == 0  # refreshes the known-good copy

    with zipfile.ZipFile(db_path) as archive:
        content = archive.read("content.xml")
    keys_sheet = content.index(b'table:name="Keys"')
    cut = content.index(b"</table:table-row>", keys_sheet) + len(b"</table:table-row>")
    damaged = rezip_ods(good_bytes, {"content.xml": content[:cut]})
    db_path.write_bytes(damaged)

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 4
    assert result.stdout == ""
    assert "content.xml is not well-formed XML" in result.stderr
    assert "mesh db restore --known-good" in result.stderr
    leaked = secret in result.output
    assert not leaked

    restored = invoke(runner, ["db", "restore", "--known-good", "--yes"], env)

    assert restored.exit_code == 0
    assert db_path.read_bytes() == good_bytes
    assert any(info.path.read_bytes() == damaged for info in backups.list_backups(db_path))
    assert invoke(runner, ["db", "verify"], env).exit_code == 0


def test_password_protected_database_is_refused_and_restore_backs_it_up(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """An encrypted file gets its own message and hint; a restore over it keeps a copy of it."""
    db_path, _ = _seed_with_private_key(seed_db)
    good_bytes = db_path.read_bytes()
    assert invoke(runner, ["db", "verify"], env).exit_code == 0

    with zipfile.ZipFile(db_path) as archive:
        manifest = archive.read("META-INF/manifest.xml")
    entry = b'manifest:full-path="content.xml" manifest:media-type="text/xml"/>'
    encrypted_entry = (
        b'manifest:full-path="content.xml" manifest:media-type="text/xml">'
        b'<manifest:encryption-data manifest:checksum-type="SHA1/1K" manifest:checksum="AAAA"/>'
        b"</manifest:file-entry>"
    )
    encrypted = rezip_ods(
        good_bytes, {"META-INF/manifest.xml": manifest.replace(entry, encrypted_entry)}
    )
    db_path.write_bytes(encrypted)

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 4
    assert result.stdout == ""
    assert "is password-protected" in result.stderr
    assert "Save with password" in result.stderr

    restored = invoke(runner, ["db", "restore", "--known-good", "--yes"], env)

    assert restored.exit_code == 0
    assert db_path.read_bytes() == good_bytes
    assert any(info.path.read_bytes() == encrypted for info in backups.list_backups(db_path))


def test_db_restore_known_good_after_two_saves_keeps_both_admin_imports(
    runner: CliRunner, env: dict[str, str]
) -> None:
    """The known-good copy must not go stale behind a *second* `save()`.

    Regression for Round 38 Batch 23: only a successful *load* used to
    refresh the known-good copy, not a `save()`. Two separate ``admin
    import`` runs each load once (refreshing the copy from ADMIN1's
    content) and then save once (previously NOT refreshing it) -- so a
    corruption after the second import's save used to restore back to
    the copy from just after the first import, silently losing ADMIN2.
    """
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    db_path = Path(env["MESHPROVISION_DB_PATH"])

    first = invoke(runner, ["admin", "import", f"ADMIN1={kp1.public_b64}"], env)
    assert first.exit_code == 0
    second = invoke(runner, ["admin", "import", f"ADMIN2={kp2.public_b64}"], env)
    assert second.exit_code == 0

    db_path.write_bytes(b"not a zip file at all")

    result = invoke(runner, ["db", "restore", "--known-good", "--yes"], env)
    assert result.exit_code == 0

    loaded = ods.load_database(db_path)
    key_refs = {row["key_ref"] for row in loaded.keys}
    assert "ADMIN1_pub" in key_refs
    assert "ADMIN2_pub" in key_refs


def test_db_restore_known_good_and_a_path_together_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    invoke(runner, ["db", "verify"], env)
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    backup_dir = backups.backup_dir_for(db_path)
    known_good = backup_dir / f"{db_path.stem}.known-good.ods"

    result = invoke(runner, ["db", "restore", str(known_good), "--known-good", "--yes"], env)

    assert result.exit_code == 2
    assert "not both" in result.stderr


def test_db_restore_neither_a_path_nor_known_good_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])

    result = invoke(runner, ["db", "restore", "--yes"], env)

    assert result.exit_code == 2


def test_db_restore_known_good_with_none_yet_is_a_clear_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])

    result = invoke(runner, ["db", "restore", "--known-good", "--yes"], env)

    assert result.exit_code == 4
    assert "No known-good copy exists yet" in result.stderr


def test_db_backup_list_shows_the_known_good_line_when_present(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    invoke(runner, ["db", "verify"], env)  # refreshes the known-good copy at the default location

    result = invoke(runner, ["db", "backup", "--list"], env)

    assert result.exit_code == 0
    assert "known-good:" in result.stdout

    as_json = invoke(runner, ["db", "backup", "--list", "--json"], env)
    document = json.loads(as_json.stdout)
    assert "known_good" in document
    assert document["known_good"]["size_bytes"] > 0


def test_db_backup_list_omits_the_known_good_line_when_absent(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    custom_dir = tmp_path / "isolated-backups"

    result = invoke(runner, ["db", "backup", "--list", "--backup-dir", str(custom_dir)], env)

    assert result.exit_code == 0
    assert "known-good:" not in result.stdout

    as_json = invoke(
        runner, ["db", "backup", "--list", "--backup-dir", str(custom_dir), "--json"], env
    )
    document = json.loads(as_json.stdout)
    assert "known_good" not in document


def test_db_list_json_reports_every_node(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(
        nodes=[
            NodeRecord(
                node_id="deadbe01",
                short_name="MT00",
                long_name="Meshtastic MT00",
                hw_model="RAK4631",
                region="EU_868",
                role="CLIENT",
                authorized_admin_keys=("ADMIN1_pub",),
                notes="a note",
            )
        ]
    )

    result = invoke(runner, ["db", "list", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["nodes"] == [
        {
            "node_id": "deadbe01",
            "short_name": "MT00",
            "long_name": "Meshtastic MT00",
            "hw_model": "RAK4631",
            "firmware_type": "vanilla",
            "firmware_version": "",
            "management": "observed",
            "region": "EU_868",
            "role": "CLIENT",
            "authorized_admin_keys": ["ADMIN1_pub"],
            "notes": "a note",
            "archived_at": None,
        }
    ]


def test_db_list_plain_text_shows_the_node_table(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(
        nodes=[
            NodeRecord(
                node_id="deadbe01", short_name="MT00", long_name="Meshtastic MT00", region="EU_868"
            )
        ]
    )

    result = invoke(runner, ["db", "list"], env)

    assert result.exit_code == 0
    assert "deadbe01" in result.stderr
    assert "MT00" in result.stderr


def test_db_list_no_nodes_reports_none_found(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[])

    result = invoke(runner, ["db", "list"], env)

    assert result.exit_code == 0
    assert "No nodes found." in result.stdout


def test_db_list_never_connects_to_a_device_or_the_network(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """The whole point: this must work with zero device/network dependency.

    No `bus.use(FakeMeshInterface(...))`/`mock_sources()` fixture is set
    up for this test at all -- if `db list` ever grew a device or network
    call, this test would hang or error rather than silently pass.
    """
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])

    result = invoke(runner, ["db", "list", "--json"], env)

    assert result.exit_code == 0


def test_db_forget_archives_a_node_without_deleting_its_row(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(
        nodes=[
            NodeRecord(
                node_id="deadbe01",
                short_name="MT00",
                authorized_admin_keys=("ADMIN1_pub",),
                notes="a note",
            )
        ]
    )

    result = invoke(runner, ["db", "forget", "deadbe01", "--yes", "--json"], env)

    assert result.exit_code == 0
    assert "Archived" in result.stderr
    document = json.loads(result.stdout)
    assert document["node_id"] == "deadbe01"
    assert document["archived_at"]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    row = loaded.nodes[0]
    assert row["node_id"] == "deadbe01"
    assert row["archived_at"]
    # Audit history preserved -- nothing about the row was deleted.
    assert row["authorized_admin_keys"] == "ADMIN1_pub"
    assert row["notes"] == "a note"


def test_db_forget_is_idempotent(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00")])
    invoke(runner, ["db", "forget", "deadbe01", "--yes"], env)

    result = invoke(runner, ["db", "forget", "deadbe01", "--yes"], env)

    assert result.exit_code == 0
    assert "already archived" in result.stderr


def test_db_forget_refuses_without_confirmation_when_non_interactive(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00")])

    result = invoke(runner, ["db", "forget", "deadbe01"], env)

    assert result.exit_code == 5
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert loaded.nodes[0]["archived_at"] == ""


def test_db_forget_unknown_node_id_fails(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[])

    result = invoke(runner, ["db", "forget", "deadbe01", "--yes"], env)

    assert result.exit_code == 3
    assert "not found" in result.stderr


def test_db_forget_rejects_an_unparseable_node_id_before_opening_the_database(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    missing = tmp_path / "no-such-db.ods"
    env["MESHPROVISION_DB_PATH"] = str(missing)

    result = invoke(runner, ["db", "forget", "zzz", "--yes"], env)

    assert result.exit_code == 2
    assert "Invalid value for 'NODE_ID': Cannot parse node id: 'zzz'" in result.stderr
    assert not missing.exists()


def test_db_list_shows_the_archived_timestamp(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00")])
    invoke(runner, ["db", "forget", "deadbe01", "--yes"], env)

    json_result = invoke(runner, ["db", "list", "--json"], env)
    document = json.loads(json_result.stdout)
    assert document["nodes"][0]["archived_at"]

    text_result = invoke(runner, ["db", "list"], env)
    assert "deadbe01" in text_result.stderr


# --- cross-database isolation and provenance (aspect 3's HIGH) --------------------


def _fleet_env(tmp_path: Path, name: str) -> dict[str, str]:
    """Build a CLI environment for one of several same-named databases.

    Each fleet's ``nodes_db.ods`` lives side by side under ``tmp_path``,
    sharing one CWD/config root but never a backup directory.
    """
    return {
        "MESHPROVISION_CONTACT": "meshprovision-tests@example.invalid",
        "MESHPROVISION_CACHE_DIR": str(tmp_path / "cache"),
        "MESHPROVISION_LOG_LEVEL": "WARNING",
        "COLUMNS": WIDE_TERMINAL_COLUMNS,
        "NO_COLOR": "1",
        "MESHPROVISION_DB_PATH": str(tmp_path / name / "nodes_db.ods"),
    }


def test_known_good_restore_never_crosses_two_same_named_databases(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Reproduces aspect 3's HIGH.

    `fleetA/nodes_db.ods` and `fleetB/nodes_db.ods` must never share a
    backup directory or known-good slot, and restoring `fleetA`'s
    known-good copy must never pull in `fleetB`'s data.
    """
    env_a = _fleet_env(tmp_path, "fleetA")
    env_b = _fleet_env(tmp_path, "fleetB")

    assert invoke(runner, ["init", "--yes"], env_a).exit_code == 0
    assert invoke(runner, ["init", "--yes"], env_b).exit_code == 0

    fleet_a_path = Path(env_a["MESHPROVISION_DB_PATH"])
    fleet_b_path = Path(env_b["MESHPROVISION_DB_PATH"])

    kp = generate_keypair()
    imported = invoke(runner, ["admin", "import", f"FLEETB={kp.public_b64}"], env_b)
    assert imported.exit_code == 0
    assert "FLEETB_pub" in {row["key_ref"] for row in ods.load_database(fleet_b_path).keys}

    # Any successful load (the init above, the import above) refreshed
    # fleetB's own known-good copy. fleetA's own `init` load did the same
    # for fleetA -- corrupt fleetA's live file to force a restore from it.
    fleet_a_path.write_bytes(b"garbage")

    result = invoke(runner, ["db", "restore", "--known-good", "--yes"], env_a)

    assert result.exit_code == 0
    restored = ods.load_database(fleet_a_path)
    assert "FLEETB_pub" not in {row["key_ref"] for row in restored.keys}

    fleet_a_backups = backups.backup_dir_for(fleet_a_path)
    fleet_b_backups = backups.backup_dir_for(fleet_b_path)
    assert fleet_a_backups.is_dir()
    assert fleet_b_backups.is_dir()
    assert fleet_a_backups != fleet_b_backups
    assert not (tmp_path / "data" / "backups").exists()


def test_prune_backups_never_shares_a_retention_budget_across_fleets(
    runner: CliRunner, tmp_path: Path
) -> None:
    env_a = _fleet_env(tmp_path, "fleetA")
    env_b = _fleet_env(tmp_path, "fleetB")
    assert invoke(runner, ["init", "--yes"], env_a).exit_code == 0
    assert invoke(runner, ["init", "--yes"], env_b).exit_code == 0
    fleet_a_path = Path(env_a["MESHPROVISION_DB_PATH"])
    fleet_b_path = Path(env_b["MESHPROVISION_DB_PATH"])

    for _ in range(3):
        assert invoke(runner, ["db", "backup", "--retention", "1"], env_a).exit_code == 0
    for _ in range(3):
        assert invoke(runner, ["db", "backup", "--retention", "1"], env_b).exit_code == 0

    assert len(backups.list_backups(fleet_a_path)) == 1
    assert len(backups.list_backups(fleet_b_path)) == 1


def test_db_restore_known_good_refuses_an_unverified_copy_by_directory_copy(
    runner: CliRunner, tmp_path: Path
) -> None:
    """A whole fleet directory copied elsewhere carries a stale known-good copy.

    It is provably not the copied-to database's own, so `--known-good`
    must refuse it, but restoring the exact same file by explicit path
    still works.
    """
    env_a = _fleet_env(tmp_path, "fleetA")
    assert invoke(runner, ["init", "--yes"], env_a).exit_code == 0
    fleet_a_dir = tmp_path / "fleetA"

    fleet_c_dir = tmp_path / "fleetC"
    shutil.copytree(fleet_a_dir, fleet_c_dir)
    env_c = dict(env_a, MESHPROVISION_DB_PATH=str(fleet_c_dir / "nodes_db.ods"))
    fleet_c_path = Path(env_c["MESHPROVISION_DB_PATH"])
    fleet_c_path.write_bytes(b"garbage")
    before_bytes = fleet_c_path.read_bytes()

    refused = invoke(runner, ["db", "restore", "--known-good", "--yes"], env_c)

    assert refused.exit_code == 4
    assert "could not be confirmed" in refused.stderr
    assert fleet_c_path.read_bytes() == before_bytes

    known_good_file = backups.backup_dir_for(fleet_c_path) / "nodes_db.known-good.ods"
    explicit = invoke(runner, ["db", "restore", str(known_good_file), "--yes"], env_c)

    assert explicit.exit_code == 0
    assert ods.load_database(fleet_c_path) is not None


def test_db_backup_list_tags_known_good_provenance(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    invoke(runner, ["db", "verify"], env)  # refreshes the known-good copy

    result = invoke(runner, ["db", "backup", "--list"], env)
    assert result.exit_code == 0
    assert "[verified]" in result.stdout

    as_json = invoke(runner, ["db", "backup", "--list", "--json"], env)
    document = json.loads(as_json.stdout)
    assert document["known_good"]["provenance"] == "verified"


def test_load_failure_hint_for_an_unverified_known_good_points_at_its_path(
    runner: CliRunner, tmp_path: Path
) -> None:
    env_a = _fleet_env(tmp_path, "fleetA")
    assert invoke(runner, ["init", "--yes"], env_a).exit_code == 0
    fleet_a_path = Path(env_a["MESHPROVISION_DB_PATH"])
    sidecar = backups.backup_dir_for(fleet_a_path) / "nodes_db.known-good.json"
    sidecar.unlink()  # simulate a copy left by an older meshprovision

    fleet_a_path.write_bytes(b"not a zip file at all")

    result = invoke(runner, ["db", "verify"], env_a)

    assert result.exit_code == 4
    assert "could not be confirmed" in result.stderr
    assert "mesh db restore --known-good" not in result.stderr


def test_db_backup_list_reports_a_legacy_backup_dir_notice(
    runner: CliRunner, tmp_path: Path
) -> None:
    env_a = _fleet_env(tmp_path, "fleetA")
    assert invoke(runner, ["init", "--yes"], env_a).exit_code == 0

    legacy_dir = tmp_path / "data" / "backups"
    legacy_dir.mkdir(parents=True)
    (legacy_dir / "nodes_db-20260101T000000.000000Z.ods").write_bytes(b"old fleet's backup")

    result = invoke(runner, ["db", "backup", "--list"], env_a)

    assert result.exit_code == 0
    assert "data" in result.stdout
    assert "backups" in result.stdout
    assert "explicit path" in result.stdout


def _symlinked_fleet_env(tmp_path: Path, *, link: Path, real_target: Path) -> dict[str, str]:
    """Build a CLI environment whose ``MESHPROVISION_DB_PATH`` is a symlink.

    Args:
        tmp_path: Pytest's per-test temporary directory, used for the
            cache directory.
        link: The symlink path handed to the CLI as ``--db-path``/
            ``MESHPROVISION_DB_PATH``.
        real_target: What ``link`` points at.
    """
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(real_target)
    return {
        "MESHPROVISION_CONTACT": "meshprovision-tests@example.invalid",
        "MESHPROVISION_CACHE_DIR": str(tmp_path / "cache"),
        "MESHPROVISION_LOG_LEVEL": "WARNING",
        "COLUMNS": WIDE_TERMINAL_COLUMNS,
        "NO_COLOR": "1",
        "MESHPROVISION_DB_PATH": str(link),
    }


def test_write_through_a_symlinked_db_path_updates_the_real_file(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Reproduces aspect 3's MEDIUM: a symlinked database is no longer split-brained.

    ``ws1/data/nodes_db.ods`` links to ``shared/nodes_db.ods``. Writing
    through the link must update the real file (not replace the link
    with a private local copy), and the write lock and backups must sit
    beside the real file, not the link.
    """
    real_target = tmp_path / "shared" / "nodes_db.ods"
    link = tmp_path / "ws1" / "data" / "nodes_db.ods"
    env_ws1 = _symlinked_fleet_env(tmp_path, link=link, real_target=real_target)

    assert invoke(runner, ["init", "--yes"], env_ws1).exit_code == 0
    assert link.is_symlink()
    assert real_target.is_file()

    kp = generate_keypair()
    imported = invoke(runner, ["admin", "import", f"WS1={kp.public_b64}"], env_ws1)
    assert imported.exit_code == 0

    assert link.is_symlink()
    real_keys = {row["key_ref"] for row in ods.load_database(real_target).keys}
    assert "WS1_pub" in real_keys

    assert lock_path_for(real_target).exists()
    assert not (link.parent / "nodes_db.ods.lock").exists()

    assert backups.backup_dir_for(real_target).is_dir()
    assert not (link.parent / "backups").exists()


def test_write_through_a_dangling_symlinked_db_path_creates_the_real_file(
    runner: CliRunner, tmp_path: Path
) -> None:
    real_target = tmp_path / "shared" / "nodes_db.ods"
    link = tmp_path / "ws1" / "data" / "nodes_db.ods"
    env_ws1 = _symlinked_fleet_env(tmp_path, link=link, real_target=real_target)

    assert invoke(runner, ["init", "--yes"], env_ws1).exit_code == 0

    assert link.is_symlink()
    assert real_target.is_file()


# ---------------------------------------------------------------------------
# Round 40 aspect 1 finding 3: a symlink-loop database path exits 4 cleanly on
# every Python version, never with a raw traceback.
# ---------------------------------------------------------------------------


def _symlink_loop_db(tmp_path: Path, env: dict[str, str]) -> Path:
    """Point ``MESHPROVISION_DB_PATH`` at a symlink loop (``a.ods -> b.ods -> a.ods``).

    Returns:
        The looping database path.
    """
    loop = tmp_path / "loop"
    loop.mkdir()
    db_path = loop / "a.ods"
    db_path.symlink_to(loop / "b.ods")
    (loop / "b.ods").symlink_to(db_path)
    env["MESHPROVISION_DB_PATH"] = str(db_path)
    return db_path


def _assert_clean_symlink_loop_exit(result: Result, db_path: Path) -> None:
    assert result.exit_code == 4, result.output
    assert f"Failed to resolve {db_path}: symlink loop" in " ".join(result.stderr.split())
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["db", "verify"],
        ["db", "list"],
        ["db", "backup"],
        ["db", "forget", "deadbe01", "--yes"],
        ["db", "restore", "--known-good", "--yes"],
    ],
    ids=["verify", "list", "backup", "forget", "restore-known-good"],
)
def test_db_command_on_a_symlink_loop_db_path_exits_cleanly(
    runner: CliRunner, env: dict[str, str], tmp_path: Path, args: list[str]
) -> None:
    """Natively, on whichever Python runs it: 3.11/3.12 raised a RuntimeError traceback."""
    db_path = _symlink_loop_db(tmp_path, env)

    _assert_clean_symlink_loop_exit(invoke(runner, args, env), db_path)


@pytest.mark.parametrize("behaviour", ["runtime_error", "unresolved"])
def test_db_verify_on_a_symlink_loop_exits_cleanly_under_either_python_behaviour(
    runner: CliRunner,
    env: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    behaviour: str,
) -> None:
    """Forces the other Python versions' resolve() behaviour, so both run on every interpreter.

    ``runtime_error`` is 3.11/3.12 (a non-strict resolve() raises
    RuntimeError); ``unresolved`` is 3.13+ (the loop comes back unresolved).
    """
    db_path = _symlink_loop_db(tmp_path, env)
    real_resolve = Path.resolve

    def fake_resolve(self: Path, strict: bool = False) -> Path:
        if self.absolute() != db_path:
            return real_resolve(self, strict=strict)
        if behaviour == "runtime_error":
            raise RuntimeError(f"Symlink loop from {str(self)!r}")
        return self.absolute()

    monkeypatch.setattr(Path, "resolve", fake_resolve)

    _assert_clean_symlink_loop_exit(invoke(runner, ["db", "verify"], env), db_path)


# ---------------------------------------------------------------------------
# Round 40 aspect 1 finding 4: `mesh db restore` blames a valid backup only
# for its own content, never for a read or write failure.
# ---------------------------------------------------------------------------


def _valid_backup(tmp_path: Path, env: dict[str, str], seed_db: Callable[..., Path]) -> Path:
    """Seed the live database and copy it, unchanged, to a backup outside its directory.

    Returns:
        The backup's path.
    """
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    backup = tmp_path / "good.ods"
    shutil.copyfile(Path(env["MESHPROVISION_DB_PATH"]), backup)
    return backup


def _restore_fails_with_a_hinted_error(
    monkeypatch: pytest.MonkeyPatch, *, after_validation: bool
) -> None:
    """Make ``restore_backup`` raise an AtomicWriteError that carries its own hint.

    Like the symlink-loop error :func:`~meshprovision.db.fs_primitives.resolve_path`
    raises: the restore's own message must embed only the inner error's
    message, or the output carries two "Hint:" lines.
    """

    def fake_restore_backup(
        backup: Path,
        target: Path,
        *,
        backup_dir: Path | None = None,
        validate: Callable[[bytes], object] | None = None,
    ) -> None:
        if after_validation and validate is not None:
            validate(backup.read_bytes())
        raise AtomicWriteError("simulated failure", path=str(target), hint="inner hint")

    monkeypatch.setattr(atomic_writer, "restore_backup", fake_restore_backup)


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="needs POSIX permission bits that bind the current user (root ignores them)",
)
def test_db_restore_write_failure_does_not_blame_a_valid_backup(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A write that fails after the backup validated blames the write, never the backup.

    Before, every failure inside the restore -- here the temp file the
    atomic replace needs, in a read-only database directory -- read
    "<BACKUP> is not a valid database ... Pick a different backup",
    sending the operator off to discard a good backup while the real
    problem stayed unfixed.
    """
    backup = _valid_backup(tmp_path, env, seed_db)
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    # The sidecar lock is opened with O_CREAT: it must already exist, or
    # the read-only directory fails the lock before the restore is reached.
    lock_path_for(db_path).touch()
    before = db_path.read_bytes()
    args = ["db", "restore", str(backup), "--yes", "--backup-dir", str(tmp_path / "backups")]
    data_dir = db_path.parent
    data_dir.chmod(0o500)
    try:
        result = invoke(runner, args, env)
    finally:
        data_dir.chmod(0o700)  # so pytest can clean tmp_path up

    stderr = " ".join(result.stderr.split())
    assert result.exit_code == 4
    assert f"Could not restore {db_path} from {backup}: Failed to create temporary file" in stderr
    assert "the backup itself is fine" in stderr
    assert "not a valid database" not in stderr
    assert stderr.count("Hint:") == 1
    assert db_path.read_bytes() == before

    _restore_fails_with_a_hinted_error(monkeypatch, after_validation=True)
    hinted = " ".join(invoke(runner, args, env).stderr.split())
    assert f"Could not restore {db_path} from {backup}: simulated failure" in hinted
    assert hinted.count("Hint:") == 1
    assert "inner hint" not in hinted


def test_db_restore_read_failure_says_nothing_was_restored(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A backup that can't be read once the restore starts is a read failure, not bad content.

    Forced through ``Path.read_bytes`` for the backup only: click checks
    BACKUP is readable up front, so a real unreadable file never gets this
    far -- only one that changes or vanishes after that check (or a
    known-good copy deleted after its provenance check) does.
    """
    backup = _valid_backup(tmp_path, env, seed_db)
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    before = db_path.read_bytes()
    real_read_bytes = Path.read_bytes

    def fake_read_bytes(self: Path) -> bytes:
        if self == backup:
            raise PermissionError(errno.EACCES, "Permission denied", str(self))
        return real_read_bytes(self)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", fake_read_bytes)
        result = invoke(runner, ["db", "restore", str(backup), "--yes"], env)

    stderr = " ".join(result.stderr.split())
    assert result.exit_code == 4
    assert f"Nothing was restored: Failed to read backup {backup}:" in stderr
    assert "still exists and is readable" in stderr
    assert "mesh db backup --list" in stderr
    assert "not a valid database" not in stderr
    assert stderr.count("Hint:") == 1
    assert db_path.read_bytes() == before

    _restore_fails_with_a_hinted_error(monkeypatch, after_validation=False)
    hinted = " ".join(invoke(runner, ["db", "restore", str(backup), "--yes"], env).stderr.split())
    assert "Nothing was restored: simulated failure" in hinted
    assert hinted.count("Hint:") == 1
    assert "inner hint" not in hinted


def _seed_future_backups(db_path: Path, backup_dir: Path) -> None:
    """Fill ``backup_dir`` to the default retention with backups named ahead of the clock."""
    future = datetime.now(tz=UTC) + timedelta(hours=1)
    for i in range(backups.DEFAULT_RETENTION):
        backups.create_backup(
            db_path, backup_dir=backup_dir, retention=0, now=future + timedelta(seconds=i)
        )


def test_db_backup_behind_the_clock_reports_a_backup_that_exists(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A clock behind existing backup names must not make the new backup prune itself."""
    monkeypatch.setattr(backups, "_warned_clock_behind", False)
    db_path = seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    backup_dir = tmp_path / "custom-backups"
    _seed_future_backups(db_path, backup_dir)

    result = invoke(runner, ["db", "backup", "--backup-dir", str(backup_dir), "--json"], env)

    assert result.exit_code == 0
    reported = Path(json.loads(result.stdout)["backup"])
    assert reported.exists()
    listed = backups.list_backups(db_path, backup_dir=backup_dir)
    assert listed[0].path == reported
    assert len(listed) == backups.DEFAULT_RETENTION


def test_db_restore_behind_the_clock_keeps_the_pre_restore_backup(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-restore backup a restore promises must survive its own prune."""
    monkeypatch.setattr(backups, "_warned_clock_behind", False)
    db_path = seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="OLD1", region="EU_868")])
    backup_dir = tmp_path / "backups"
    _seed_future_backups(db_path, backup_dir)
    restore_from = backups.list_backups(db_path, backup_dir=backup_dir)[0].path
    seed_db(nodes=[NodeRecord(node_id="deadbe02", short_name="NEW2", region="EU_868")])
    before_restore = db_path.read_bytes()

    result = invoke(
        runner, ["db", "restore", str(restore_from), "--yes", "--backup-dir", str(backup_dir)], env
    )

    assert result.exit_code == 0
    assert db_path.read_bytes() == restore_from.read_bytes()
    listed = backups.list_backups(db_path, backup_dir=backup_dir)
    assert listed[0].path.read_bytes() == before_restore
    assert len(listed) == backups.DEFAULT_RETENTION


def test_db_backup_list_through_a_differently_named_symlink_shows_every_backup(
    runner: CliRunner, tmp_path: Path
) -> None:
    """`db backup --list` through the link showed none of the backups saves had taken.

    Saves named them after the real file; the listing looked for the link's name.
    """
    real_target = tmp_path / "shared" / "nodes_db.ods"
    link = tmp_path / "ws1" / "fleet.ods"
    env_link = _symlinked_fleet_env(tmp_path, link=link, real_target=real_target)
    env_real = {**env_link, "MESHPROVISION_DB_PATH": str(real_target)}

    assert invoke(runner, ["init", "--yes"], env_link).exit_code == 0
    kp = generate_keypair()
    assert invoke(runner, ["admin", "import", f"WS1={kp.public_b64}"], env_link).exit_code == 0
    assert invoke(runner, ["db", "backup"], env_link).exit_code == 0

    via_link = invoke(runner, ["db", "backup", "--list", "--json"], env_link)
    via_real = invoke(runner, ["db", "backup", "--list", "--json"], env_real)

    assert via_link.exit_code == 0
    document = json.loads(via_link.stdout)
    paths = [Path(entry["path"]) for entry in document["backups"]]
    assert len(paths) >= 2
    assert all(path.name.startswith("nodes_db-") for path in paths)
    assert document == json.loads(via_real.stdout)
    assert Path(document["known_good"]["path"]).name == "nodes_db.known-good.ods"
    assert document["known_good"]["provenance"] == "verified"
