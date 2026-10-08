"""``mesh db verify``: the database integrity and key-hygiene audit, run as a real CLI."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db import ods_write
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.observed_keys import observed_key_ref
from meshprovision.db.schema import KeyOrigin, KeyType
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
    pub, priv = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
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
    binary, skipped where it isn't installed. ``soffice`` gets a fresh
    profile and a ``HOME``/``XDG_CACHE_HOME`` under ``tmp_path``, so it
    never reads or writes the operator's own LibreOffice profile, and two
    runs at once never share one.
    """
    kp = generate_keypair()
    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    pub, priv = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    db_path = seed_db(nodes=[node], keys=[pub, priv])

    out_dir = tmp_path / "libreoffice_out"
    subprocess.run(
        [
            _SOFFICE,
            "--headless",
            f"-env:UserInstallation={(tmp_path / 'lo_profile').as_uri()}",
            "--convert-to",
            "ods",
            "--outdir",
            str(out_dir),
            str(db_path),
        ],
        check=True,
        capture_output=True,
        timeout=120,
        env={
            **os.environ,
            "HOME": str(tmp_path / "home"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
        },
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
    weak_pub = KeyRecord.from_material(
        "deadbe01", KeyType.ADMIN_PUBLIC, bytes(32), origin=KeyOrigin.CAPTURED
    )
    seed_db(nodes=[node], keys=[weak_pub])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    weak_key_problems = [p for p in document["problems"] if p["kind"] == "weak_key"]
    assert weak_key_problems
    assert any(p["severity"] == "critical" for p in weak_key_problems)
    assert any("all_zero" in p["message"] for p in weak_key_problems)


def test_db_verify_finds_blocklist_next_to_a_db_path_outside_the_cwd(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    """The DB-sibling blocklist candidate is used regardless of the CLI's cwd.

    ``--db-path``/``MESHPROVISION_DB_PATH`` here points well outside the
    autouse-chdir'd cwd, with no ``./data/known_bad_keys.txt`` anywhere
    near it -- only a blocklist sitting next to the database itself. On
    revert (no ``db_path`` plumbing through ``CliContext.known_bad_keys``),
    this entry is never found and the run reports "Database OK." instead.
    """
    project = tmp_path / "elsewhere" / "data"
    project.mkdir(parents=True)
    custom_db_path = project / "nodes_db.ods"
    kp = generate_keypair()
    (project / "known_bad_keys.txt").write_text(f"{kp.public_b64}\n")

    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    blocked_admin = KeyRecord.from_material(
        "deadbe01", KeyType.ADMIN_PUBLIC, kp.public, origin=KeyOrigin.CAPTURED
    )
    ods_write.write_database(
        custom_db_path,
        nodes=[node.to_row()],
        keys=[blocked_admin.to_row()],
        backup=False,
    )

    custom_env = dict(env)
    custom_env["MESHPROVISION_DB_PATH"] = str(custom_db_path)

    result = invoke(runner, ["db", "verify", "--json"], custom_env)

    assert result.exit_code == 6
    document = json.loads(result.stdout)
    weak_key_problems = [p for p in document["problems"] if p["kind"] == "weak_key"]
    assert weak_key_problems
    assert any("blocklist" in p["message"] for p in weak_key_problems)


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
    pub_a, priv_a = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    pub_b, priv_b = KeyRecord.for_keypair("deadbe02", kp, origin=KeyOrigin.CAPTURED)
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
    pub_a, priv_a = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    pub_b, priv_b = KeyRecord.for_keypair("deadbe02", kp, origin=KeyOrigin.CAPTURED)
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
    pub_a, priv_a = KeyRecord.for_keypair("cafe", kp, origin=KeyOrigin.IMPORTED)
    pub_b, priv_b = KeyRecord.for_keypair("face", kp, origin=KeyOrigin.IMPORTED)
    seed_db(nodes=[], keys=[pub_a, priv_a, pub_b, priv_b])

    result = invoke(runner, ["db", "verify", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "duplicate_public_key" not in kinds
    assert "alias_public_key" in kinds


def test_db_verify_shared_observed_ref_across_two_nodes_is_a_warning_unless_strict(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """The same mesh-adopt-minted observed-* ref on two nodes is the normal shared-admin-key shape.

    A cloned admin key neither node has had imported resolves, under the
    content-addressed observed-key scheme, to one shared Keys row rather
    than two distinct rows holding equal material -- so this is a
    different shape than ``test_db_verify_duplicate_public_key_across_
    nodes_exits_six`` above. It is not the CVE-2025-52464 device-cloning
    signature -- one admin key authorized on many nodes is the intended
    fleet setup -- so it is a WARNING nudging the operator to `mesh admin
    import` it, not a CRITICAL alarm.
    """
    kp = generate_keypair()
    ref = observed_key_ref(kp.public)
    owner = ref.removesuffix("_pub")
    node_a = NodeRecord(node_id="deadbe01", short_name="MT00", authorized_admin_keys=(ref,))
    node_b = NodeRecord(node_id="deadbe02", short_name="MT01", authorized_admin_keys=(ref,))
    observed_pub = KeyRecord.from_material(
        owner, KeyType.ADMIN_PUBLIC, kp.public, origin=KeyOrigin.IMPORTED
    )
    seed_db(nodes=[node_a, node_b], keys=[observed_pub])

    lenient = invoke(runner, ["db", "verify", "--json"], env)

    assert lenient.exit_code == 0
    document = json.loads(lenient.stdout)
    kinds = {problem["kind"] for problem in document["problems"]}
    assert "unimported_admin_key" in kinds
    assert "duplicate_public_key" not in kinds
    warning = next(p for p in document["problems"] if p["kind"] == "unimported_admin_key")
    assert "CVE" not in warning["message"]
    assert "deadbe01, deadbe02" in warning["message"]

    strict = invoke(runner, ["db", "verify", "--strict"], env)
    assert strict.exit_code == 4


def test_db_verify_alias_public_key_is_a_warning_unless_strict(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    kp = generate_keypair()
    node = NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")
    node_pub, node_priv = KeyRecord.for_keypair("deadbe01", kp, origin=KeyOrigin.CAPTURED)
    label_pub, label_priv = KeyRecord.for_keypair("ADMIN1", kp, origin=KeyOrigin.IMPORTED)
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
    pub, _ = KeyRecord.for_keypair("ADMIN1", kp_a, origin=KeyOrigin.IMPORTED)
    _, priv = KeyRecord.for_keypair("ADMIN1", kp_b, origin=KeyOrigin.IMPORTED)
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
    _, priv = KeyRecord.for_keypair("ADMIN1", kp, origin=KeyOrigin.IMPORTED)
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


def test_db_timestamp_cell_out_of_range_in_utc_is_a_validation_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """A hand-edited timestamp that overflows when shifted to UTC exits 4, not 1.

    ``0001-01-01T00:00:00+01:00`` parses, but is one hour before year 1 in
    UTC; before the fix ``mesh db verify`` and ``mesh db list`` crashed with
    an ``OverflowError`` traceback instead of naming the cell.
    """
    from tests.unit.conftest import edit_ods_cell

    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="MT00", region="EU_868")])
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    edit_ods_cell(db_path, "Nodes", "first_added_ts", 2, "0001-01-01T00:00:00+01:00")

    for command in (["db", "verify"], ["db", "list"]):
        result = invoke(runner, command, env)
        assert result.exit_code == 4, command
        assert "'first_added_ts' is not a valid timestamp" in result.stderr
        assert "Use ISO-8601" in result.stderr
