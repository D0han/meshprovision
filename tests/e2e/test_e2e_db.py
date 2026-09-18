"""``mesh db verify``/``backup``/``restore`` (schema, cross-references, weak-key audit)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyType
from meshprovision.provisioning.observed_keys import observed_key_ref
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_SOFFICE = shutil.which("soffice")


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


@pytest.mark.skipif(_SOFFICE is None, reason="LibreOffice (soffice) is not installed")
def test_db_verify_survives_a_real_libreoffice_save(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    tmp_path: Path,
) -> None:
    """Regression test for the exact operator report this guards against.

    Opening the database in LibreOffice Calc, resizing a column, and
    saving must not break ``mesh db verify`` -- simulated everywhere else
    in the suite (``tests.unit.conftest.libreoffice_round_trip``, kept
    deterministic and soffice-free) but exercised here against the real
    binary, skipped where it isn't installed.
    """
    kp = generate_keypair()
    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    pub, priv = KeyRecord.for_keypair("deadbe01", kp)
    db_path = seed_db(nodes=[node], keys=[pub, priv])

    out_dir = tmp_path / "libreoffice_out"
    subprocess.run(
        [
            _SOFFICE,
            "--headless",
            "--convert-to",
            "ods",
            "--outdir",
            str(out_dir),
            str(db_path),
        ],
        check=True,
        capture_output=True,
        timeout=120,
    )
    resaved = out_dir / db_path.name
    assert resaved.is_file()
    shutil.copyfile(resaved, db_path)

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 0
    assert "Database OK." in result.stderr


def test_db_verify_all_zero_admin_key_exits_six(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """Regression test: mesh db verify's weak-key audit wiring is exercised end to end.

    verify_database calls weakkeys.audit_public_key/audit_private_key on
    every Keys sheet row directly -- distinct from, and never exercised
    by, the duplicate-key or admin-key-mismatch checks that already have
    e2e coverage. A bug here (e.g. swapping which key_type gets audited,
    or known_bad not actually reaching the call) would let a
    structurally broken key sit in the database with `mesh db verify`
    still reporting "Database OK."
    """
    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    weak_pub = KeyRecord.from_material("deadbe01", KeyType.ADMIN_PUBLIC, bytes(32))
    seed_db(nodes=[node], keys=[weak_pub])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    weak_key_problems = [p for p in document["problems"] if p["kind"] == "weak_key"]
    assert weak_key_problems
    assert any(p["severity"] == "critical" for p in weak_key_problems)
    assert any("all_zero" in p["message"] for p in weak_key_problems)


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
    """A failed template load must be a visible, --json-observable degradation.

    Regression test: this used to report "Database OK." even though the
    template cross-check never ran -- a --json consumer had no way to
    tell "ran clean" apart from "never ran." It now surfaces as its own
    warning problem, both in text mode and in --json.
    """
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    broken = tmp_path / "broken.yaml"
    broken.write_text("not: [a valid: template", encoding="utf-8")
    env["MESHPROVISION_TEMPLATE_PATH"] = str(broken)

    result = invoke(runner, ["db", "verify"], env)

    assert result.exit_code == 0
    assert "Could not load template for cross-checking" in result.stderr
    assert "Database OK." not in result.stderr
    assert "Template cross-check skipped" in result.stderr

    json_result = invoke(runner, ["db", "verify", "--json"], env)
    assert json_result.exit_code == 0
    document = json.loads(json_result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "template_unavailable" in kinds


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


def test_db_verify_duplicate_public_key_not_yet_adopted_still_exits_six(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """Regression test: a clone between two not-yet-adopted devices is still CRITICAL.

    Registering an admin key via `mesh admin import` ahead of adopting or
    provisioning the device it belongs to is this project's own
    documented onboarding order -- a genuine CVE-2025-52464 clone must
    not be downgraded to a mere alias warning just because neither
    colliding node has a Nodes sheet row yet.
    """
    kp = generate_keypair()
    pub_a, priv_a = KeyRecord.for_keypair("deadbe01", kp)
    pub_b, priv_b = KeyRecord.for_keypair("deadbe02", kp)
    seed_db(nodes=[], keys=[pub_a, priv_a, pub_b, priv_b])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "duplicate_public_key" in kinds
    critical = next(p for p in document["problems"] if p["kind"] == "duplicate_public_key")
    assert "CVE-2025-52464" in critical["message"]


def test_db_verify_hex_shaped_labels_sharing_a_key_are_an_alias_not_critical(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """Regression test: a short hex-looking template label is not a device node id.

    NodeId.try_parse accepts a 1-7 character all-hex string (its case
    (e), meant for lorastats/human-typed shortcuts elsewhere) -- an
    admin_nodes template label that happens to look hex-shaped (e.g.
    "cafe", "face") must not be mistaken for a real <node_id>_pub ref,
    or two labels aliasing the same key (this module's own documented
    legitimate/benign case) would be wrongly reported as a
    CVE-2025-52464 clone.
    """
    kp = generate_keypair()
    pub_a, priv_a = KeyRecord.for_keypair("cafe", kp)
    pub_b, priv_b = KeyRecord.for_keypair("face", kp)
    seed_db(nodes=[], keys=[pub_a, priv_a, pub_b, priv_b])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "duplicate_public_key" not in kinds
    assert "alias_public_key" in kinds


def test_db_verify_shared_observed_ref_across_two_nodes_exits_six(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """The same mesh-adopt-minted observed-* ref on two nodes is the clone signature.

    A cloned admin key neither node has had imported resolves, under the
    content-addressed observed-key scheme, to one shared Keys row rather
    than two distinct rows holding equal material -- so this is a
    different shape than ``test_db_verify_duplicate_public_key_across_
    nodes_exits_six`` above, and must be caught separately.
    """
    kp = generate_keypair()
    ref = observed_key_ref(kp.public)
    owner = ref.removesuffix("_pub")
    node_a = NodeRecord(node_id="deadbe01", short_name="MT00", authorized_admin_keys=(ref,))
    node_b = NodeRecord(node_id="deadbe02", short_name="MT01", authorized_admin_keys=(ref,))
    observed_pub = KeyRecord.from_material(owner, KeyType.ADMIN_PUBLIC, kp.public)
    seed_db(nodes=[node_a, node_b], keys=[observed_pub])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "duplicate_public_key" in kinds
    critical = next(p for p in document["problems"] if p["kind"] == "duplicate_public_key")
    assert "CVE-2025-52464" in critical["message"]
    assert "deadbe01, deadbe02" in critical["message"]


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


def test_db_verify_admin_key_mismatch_exits_six(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """A mismatched admin keypair is critical, matching audit_keypair's own rating.

    Regression test: this used to report severity "error" (exit 4), a
    lesser finding than weakkeys.audit_keypair's CONSISTENCY check would
    give the identical real-world condition (corruption or a partial
    restore, firmware issue #7449) -- but audit_keypair itself is never
    actually invoked from `mesh db verify`, so private_key_mismatch's
    severity was the only one that mattered in practice.
    """
    kp_a, kp_b = generate_keypair(), generate_keypair()
    pub, _ = KeyRecord.for_keypair("ADMIN1", kp_a)
    _, priv = KeyRecord.for_keypair("ADMIN1", kp_b)
    seed_db(keys=[pub, priv])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    problem = next(p for p in document["problems"] if p["kind"] == "admin_key_mismatch")
    assert problem["severity"] == "critical"


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

    # The pre-restore content was itself backed up -- a restore is reversible.
    assert len(list(backup_dir.glob("*.ods"))) == 2


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
    """A corrupt/non-ODS backup file must fail loudly, not leave a mysteriously-broken database."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    bad_backup = tmp_path / "not-an-ods-file.ods"
    bad_backup.write_text("not a zip file")

    result = invoke(
        runner, ["db", "restore", str(bad_backup), "--yes", "--backup-dir", str(backup_dir)], env
    )

    assert result.exit_code == 4
    assert "does not load as a valid database" in result.stderr
    assert "mesh db backup --list" in result.stderr


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


def test_db_restore_known_good_and_a_path_together_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    invoke(runner, ["db", "verify"], env)
    backup_dir = Path("data/backups")
    known_good = backup_dir / f"{Path(env['MESHPROVISION_DB_PATH']).stem}.known-good.ods"

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
            "management": "template",
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

    assert result.exit_code != 0
    assert "not found" in result.stderr


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
