"""``mesh db verify`` (schema, cross-references, weak-key audit) and ``mesh db backup``."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def test_db_verify_clean_database_ok(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    kp = generate_keypair()
    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    pub, priv = KeyRecord.for_keypair("deadbe01", kp)
    seed_db(nodes=[node], keys=[pub, priv])

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 0
    assert "Database OK." in result.stderr


def test_db_verify_unresolved_admin_ref_exits_four(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    node = NodeRecord(
        node_id="deadbe01",
        short_name="MT00",
        region="EU_868",
        authorized_admin_keys=("MISSING_pub",),
    )
    seed_db(nodes=[node])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 4
    document = json.loads(result.stdout)
    assert document["problems"]
    assert document["problems"][0]["kind"] == "unresolved_admin_ref"


def test_db_verify_unresolved_template_ref_exits_four(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["GHOST"]))

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 4
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "unresolved_template_ref" in kinds


def test_db_verify_degrades_when_the_template_exceeds_the_admin_key_limit(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    write_template: Callable[..., Path],
) -> None:
    node = NodeRecord(
        node_id="deadbe01",
        short_name="MT00",
        region="EU_868",
        authorized_admin_keys=("MISSING_pub",),
    )
    seed_db(nodes=[node])
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["A", "B", "C", "D"]))

    result = invoke(runner, ["db", "verify", "--json"], env)

    # Exit 4 (the database's own findings), not 5 (the provisioning-domain
    # error the unguarded AdminKeyCapacityError produced).
    assert result.exit_code == 4
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "unresolved_admin_ref" in kinds
    assert "Could not load template for cross-checking" in result.stderr
    assert "at most 3" in result.stderr


def test_db_verify_degrades_when_the_template_is_unparseable(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    broken = tmp_path / "broken.yaml"
    broken.write_text("not: [a valid: template", encoding="utf-8")
    env["MESHPROVISION_TEMPLATE_PATH"] = str(broken)

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 0
    assert "Could not load template for cross-checking" in result.stderr
    assert "Database OK." in result.stderr


def test_db_verify_duplicate_public_key_across_nodes_exits_six(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    kp = generate_keypair()
    node_a = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    node_b = NodeRecord(node_id="deadbe02", short_name="MT01", region="EU_868")
    pub_a, priv_a = KeyRecord.for_keypair("deadbe01", kp)
    pub_b, priv_b = KeyRecord.for_keypair("deadbe02", kp)
    seed_db(nodes=[node_a, node_b], keys=[pub_a, priv_a, pub_b, priv_b])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "duplicate_public_key" in kinds
    critical = next(p for p in document["problems"] if p["kind"] == "duplicate_public_key")
    assert "CVE-2025-52464" in critical["message"]


def test_db_verify_alias_public_key_is_a_warning_unless_strict(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    kp = generate_keypair()
    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    node_pub, node_priv = KeyRecord.for_keypair("deadbe01", kp)
    label_pub, label_priv = KeyRecord.for_keypair("ADMIN1", kp)
    seed_db(nodes=[node], keys=[node_pub, node_priv, label_pub, label_priv])

    lenient = invoke(runner, ["db", "verify", "--json"], env)
    assert lenient.exit_code == 0
    lenient_doc = json.loads(lenient.stdout)
    kinds = {problem["kind"] for problem in lenient_doc["problems"]}
    assert "alias_public_key" in kinds

    strict = invoke(runner, ["db", "verify", "--strict"], env)
    assert strict.exit_code == 4


def test_db_verify_admin_key_mismatch_exits_four_without_strict(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    kp_a, kp_b = generate_keypair(), generate_keypair()
    pub, _ = KeyRecord.for_keypair("ADMIN1", kp_a)
    _, priv = KeyRecord.for_keypair("ADMIN1", kp_b)
    seed_db(keys=[pub, priv])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 4
    document = json.loads(result.stdout)
    problem = next(p for p in document["problems"] if p["kind"] == "admin_key_mismatch")
    assert problem["severity"] == "error"


def test_db_verify_does_not_report_an_orphan_private_key_as_a_mismatch(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    kp = generate_keypair()
    _, priv = KeyRecord.for_keypair("ADMIN1", kp)
    seed_db(keys=[priv])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "admin_key_mismatch" not in kinds


@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_db_verify_insecure_permissions_is_a_warning_unless_strict(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    db_path.chmod(0o644)

    lenient = invoke(runner, ["db", "verify", "--json"], env)
    assert lenient.exit_code == 0
    lenient_doc = json.loads(lenient.stdout)
    problem = next(p for p in lenient_doc["problems"] if p["kind"] == "insecure_permissions")
    assert problem["severity"] == "warning"

    strict = invoke(runner, ["db", "verify", "--strict"], env)
    assert strict.exit_code == 4


def test_db_verify_coerced_cell_is_a_warning_unless_strict(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    from tests.unit.conftest import edit_ods_cell

    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    seed_db(nodes=[node])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    edit_ods_cell(db_path, "Nodes", "notes", 2, "1234", value_type="float")

    lenient = invoke(runner, ["db", "verify", "--json"], env)
    assert lenient.exit_code == 0
    lenient_doc = json.loads(lenient.stdout)
    problem = next(p for p in lenient_doc["problems"] if p["kind"] == "coerced_cell")
    assert problem["severity"] == "warning"

    strict = invoke(runner, ["db", "verify", "--strict"], env)
    assert strict.exit_code == 4


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


def test_db_backup_missing_database_exits_four(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    env = dict(env)
    env["MESHPROVISION_DB_PATH"] = str(tmp_path / "does-not-exist.ods")

    result = invoke(runner, ["db", "backup"], env)

    assert result.exit_code == 4
