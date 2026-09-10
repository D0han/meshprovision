"""The full admin bootstrap sequence, ``mesh admin import``, and ``mesh admin list``.

The trap this module is built to avoid: ``run_provision`` (which ``mesh
admin bootstrap`` reuses wholesale) calls ``resolve_admin_keys`` for
*every* entry of ``template.admin_nodes``, so a template cannot already
list ``ADMIN2``/``ADMIN3`` while bootstrapping ``ADMIN1`` -- the template
must grow between runs, matching the exact chicken-and-egg sequence the
project's own README documents.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto import weakkeys
from meshprovision.crypto.keys import encode_key, generate_keypair
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.errors import ExitCode
from tests.e2e.conftest import FakeMeshInterface, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


def test_full_admin_bootstrap_sequence_and_consumption(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    # Step 1: bootstrap ADMIN1 on aaaa0001, with an empty admin_nodes template.
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=[]))
    bus.use(FakeMeshInterface("aaaa0001"))
    step1 = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN1", "--yes"],
        env,
    )
    assert step1.exit_code == 0

    # Step 2: bootstrap ADMIN2 on aaaa0002; template now lists ADMIN1.
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["ADMIN1"]))
    bus.use(FakeMeshInterface("aaaa0002"))
    step2 = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN2", "--yes"],
        env,
    )
    assert step2.exit_code == 0
    assert "Authorized on !aaaa0002: ADMIN1_pub" in step2.stderr

    # Step 3: bootstrap ADMIN3 on aaaa0003; template now lists ADMIN1, ADMIN2.
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["ADMIN1", "ADMIN2"]))
    bus.use(FakeMeshInterface("aaaa0003"))
    step3 = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN3", "--yes"],
        env,
    )
    assert step3.exit_code == 0
    assert "ADMIN1_pub, ADMIN2_pub" in step3.stderr

    db_path = env["MESHPROVISION_DB_PATH"]
    loaded = ods.load_database(Path(db_path))
    keys_by_ref = {row["key_ref"]: KeyRecord.from_row(row) for row in loaded.keys}
    expected_refs = {
        "aaaa0001_pub",
        "aaaa0001_priv",
        "aaaa0002_pub",
        "aaaa0002_priv",
        "aaaa0003_pub",
        "aaaa0003_priv",
        "ADMIN1_pub",
        "ADMIN1_priv",
        "ADMIN2_pub",
        "ADMIN2_priv",
        "ADMIN3_pub",
        "ADMIN3_priv",
    }
    assert set(keys_by_ref) == expected_refs
    for node_hex, admin_ref in (
        ("aaaa0001", "ADMIN1"),
        ("aaaa0002", "ADMIN2"),
        ("aaaa0003", "ADMIN3"),
    ):
        node_material = keys_by_ref[f"{node_hex}_pub"].material()
        admin_material = keys_by_ref[f"{admin_ref}_pub"].material()
        assert node_material == admin_material

    # Step 4: a normal `mesh provision` on bbbb0001 that consumes all three admins.
    env["MESHPROVISION_TEMPLATE_PATH"] = str(
        write_template(admin_nodes=["ADMIN1", "ADMIN2", "ADMIN3"])
    )
    iface4 = bus.use(FakeMeshInterface("bbbb0001"))
    step4 = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert step4.exit_code == 0

    assert len(iface4.admin_keys) == 3
    admin_materials = {
        keys_by_ref["ADMIN1_pub"].material(),
        keys_by_ref["ADMIN2_pub"].material(),
        keys_by_ref["ADMIN3_pub"].material(),
    }
    assert set(iface4.admin_keys) == admin_materials

    loaded2 = ods.load_database(Path(db_path))
    nodes_by_id = {row["node_id"]: row for row in loaded2.nodes}
    assert nodes_by_id["bbbb0001"]["authorized_admin_keys"] == "ADMIN1_pub;ADMIN2_pub;ADMIN3_pub"

    # Step 5: pending cross-authorizations.
    admin_list = invoke(runner, ["admin", "list", "--json"], env)
    assert admin_list.exit_code == 0
    document = json.loads(admin_list.stdout)
    admins = {entry["ref"]: entry for entry in document["admins"]}
    assert set(admins) == {"ADMIN1", "ADMIN2", "ADMIN3"}

    assert admins["ADMIN1"]["authorized_on"] == ["aaaa0002", "aaaa0003", "bbbb0001"]
    assert admins["ADMIN1"]["pending_on"] == []
    assert admins["ADMIN2"]["pending_on"] == ["aaaa0001"]
    assert admins["ADMIN3"]["pending_on"] == ["aaaa0001", "aaaa0002"]

    for entry in admins.values():
        assert entry["present"] is True
        assert entry["has_private"] is True
        assert entry["in_template"] is True
        assert entry["fingerprint"].startswith("sha256:")

    assert not _BASE64_KEY_RE.search(admin_list.stdout)
    assert not _BASE64_KEY_RE.search(admin_list.stderr)


def test_admin_bootstrap_inherits_the_enroll_gate(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED)
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "--enroll" in result.stderr


def test_admin_import_registers_a_held_public_key(runner: CliRunner, env: dict[str, str]) -> None:
    kp = generate_keypair()
    result = invoke(runner, ["admin", "import", f"ADMIN9={kp.public_b64}"], env)

    assert result.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert "ADMIN9_pub" in rows
    assert "ADMIN9_priv" not in rows
    assert KeyRecord.from_row(rows["ADMIN9_pub"]).material() == kp.public

    assert "sha256:" in result.stderr
    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_admin_import_reimporting_identical_material_is_a_noop(
    runner: CliRunner, env: dict[str, str]
) -> None:
    kp = generate_keypair()
    first = invoke(runner, ["admin", "import", f"ADMIN9={kp.public_b64}"], env)
    assert first.exit_code == 0

    second = invoke(runner, ["admin", "import", f"ADMIN9={kp.public_b64}"], env)
    assert second.exit_code == 0
    assert "already registered" in second.stderr


def test_admin_import_differing_material_without_force_is_refused(
    runner: CliRunner, env: dict[str, str]
) -> None:
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    first = invoke(runner, ["admin", "import", f"ADMIN9={kp1.public_b64}"], env)
    assert first.exit_code == 0

    refused = invoke(runner, ["admin", "import", f"ADMIN9={kp2.public_b64}"], env)
    assert refused.exit_code == 6

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(rows["ADMIN9_pub"]).material() == kp1.public

    forced = invoke(runner, ["admin", "import", f"ADMIN9={kp2.public_b64}", "--force"], env)
    assert forced.exit_code == 0
    loaded2 = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows2 = {row["key_ref"]: row for row in loaded2.keys}
    assert KeyRecord.from_row(rows2["ADMIN9_pub"]).material() == kp2.public


def test_admin_import_duplicate_material_under_a_second_ref(
    runner: CliRunner, env: dict[str, str]
) -> None:
    kp = generate_keypair()
    first = invoke(runner, ["admin", "import", f"ADMIN9={kp.public_b64}"], env)
    assert first.exit_code == 0

    refused = invoke(runner, ["admin", "import", f"ADMIN10={kp.public_b64}"], env)
    assert refused.exit_code == 6
    assert "already registered" in refused.stderr

    forced = invoke(runner, ["admin", "import", f"ADMIN10={kp.public_b64}", "--force"], env)
    assert forced.exit_code == 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"]: row for row in loaded.keys}
    assert KeyRecord.from_row(rows["ADMIN10_pub"]).material() == kp.public


def test_admin_import_all_zero_key_is_refused(runner: CliRunner, env: dict[str, str]) -> None:
    zero_b64 = base64.b64encode(bytes(32)).decode("ascii")
    result = invoke(runner, ["admin", "import", f"ADMIN9={zero_b64}"], env)
    assert result.exit_code == 6


def test_provision_refuses_to_authorize_a_force_imported_weak_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    small_order_b64 = base64.b64encode(weakkeys.SMALL_ORDER_POINTS[2]).decode("ascii")
    imported = invoke(runner, ["admin", "import", f"ADMIN9={small_order_b64}", "--force"], env)
    assert imported.exit_code == 0

    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["ADMIN9"]))
    bus.use(FakeMeshInterface("cccc0001"))
    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run", "--json"], env)

    assert result.exit_code == 0
    key_plan = json.loads(result.stdout)["plan"]["key_plan"]
    assert key_plan["rejected_admin_key_refs"] == ["ADMIN9_pub"]
    assert key_plan["desired_admin_key_refs"] == []
    assert key_plan["admin_key_count"] == 0

    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_provision_allow_weak_admin_key_authorizes_a_force_imported_weak_admin_key(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
) -> None:
    small_order_b64 = base64.b64encode(weakkeys.SMALL_ORDER_POINTS[2]).decode("ascii")
    imported = invoke(runner, ["admin", "import", f"ADMIN9={small_order_b64}", "--force"], env)
    assert imported.exit_code == 0

    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["ADMIN9"]))
    bus.use(FakeMeshInterface("cccc0002"))
    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--dry-run", "--json", "--allow-weak-admin-key"],
        env,
    )

    assert result.exit_code == 0
    document = json.loads(result.stdout)["plan"]
    assert document["key_plan"]["desired_admin_key_refs"] == ["ADMIN9_pub"]
    assert document["key_plan"]["rejected_admin_key_refs"] == []
    forced = [w for w in document["warnings"] if w["code"] == "resolved_admin_key_forced"]
    assert len(forced) == 1
    assert "ADMIN9_pub" in forced[0]["message"]

    assert not _BASE64_KEY_RE.search(result.stdout)
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_admin_import_malformed_assignment_missing_equals(
    runner: CliRunner, env: dict[str, str]
) -> None:
    result = invoke(runner, ["admin", "import", "ADMIN9"], env)
    assert result.exit_code == 2
    assert "ADMIN9" in result.stderr


@pytest.mark.parametrize("suffix", ["_pub", "_priv", "_psk"])
def test_admin_import_ref_with_reserved_suffix_is_rejected(
    runner: CliRunner, env: dict[str, str], suffix: str
) -> None:
    """All three reserved suffixes are rejected, not just ``_pub``.

    meshprovision appends each of these itself when resolving Keys sheet
    rows, so an operator ref ending in any of them would collide.
    """
    kp = generate_keypair()
    result = invoke(runner, ["admin", "import", f"ADMIN9{suffix}={kp.public_b64}"], env)
    assert result.exit_code == 2
    assert suffix in result.stderr
    assert not _BASE64_KEY_RE.search(result.stderr)


def test_admin_import_multiple_assignments_reports_registered_and_skipped(
    runner: CliRunner, env: dict[str, str]
) -> None:
    kp_a = generate_keypair()
    kp_b = generate_keypair()

    first = invoke(runner, ["admin", "import", f"ADMIN_A={kp_a.public_b64}"], env)
    assert first.exit_code == 0

    result = invoke(
        runner,
        [
            "admin",
            "import",
            f"ADMIN_A={kp_a.public_b64}",
            f"ADMIN_B={kp_b.public_b64}",
            "--json",
        ],
        env,
    )
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    registered_refs = {entry["ref"] for entry in document["registered"]}
    skipped_refs = {entry["ref"] for entry in document["skipped"]}
    assert registered_refs == {"ADMIN_B"}
    assert skipped_refs == {"ADMIN_A"}

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    rows = {row["key_ref"] for row in loaded.keys}
    assert {"ADMIN_A_pub", "ADMIN_B_pub"} <= rows


def test_admin_import_clears_the_key_from_every_nodes_unregistered_list(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """Registering a key must not leave it recorded as unregistered elsewhere.

    ``mesh adopt`` records an admin key it cannot resolve to a ref onto
    the adopting node. Importing that same material under a ref makes the
    field stale, so ``mesh adopt``'s duplicate warning would keep calling
    a registered key "unregistered" until the node is re-adopted.
    """
    adopted_kp = generate_keypair()
    other_kp = generate_keypair()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="cafe0001",
                unregistered_admin_keys=(
                    encode_key(adopted_kp.public),
                    encode_key(other_kp.public),
                ),
            ),
            NodeRecord(node_id="cafe0002", unregistered_admin_keys=(encode_key(other_kp.public),)),
        ]
    )

    result = invoke(runner, ["admin", "import", f"FRIEND={adopted_kp.public_b64}"], env)
    assert result.exit_code == 0

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    nodes = {row["node_id"]: NodeRecord.from_row(row) for row in loaded.nodes}
    assert nodes["cafe0001"].unregistered_admin_key_materials() == (other_kp.public,)
    assert nodes["cafe0002"].unregistered_admin_key_materials() == (other_kp.public,)


def test_admin_list_table_shows_the_weak_key_audit_result(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    bad_b64 = base64.b64encode(weakkeys.SMALL_ORDER_POINTS[1]).decode("ascii")
    assert (
        invoke(runner, ["admin", "import", f"ADMIN_BAD={bad_b64}", "--force"], env).exit_code == 0
    )

    kp = generate_keypair()
    assert invoke(runner, ["admin", "import", f"ADMIN_OK={kp.public_b64}"], env).exit_code == 0

    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["ADMIN_OK", "ADMIN_BAD"]))
    result = invoke(runner, ["admin", "list"], env)

    assert result.exit_code == 0
    assert result.stdout == ""

    lines = result.stderr.splitlines()
    header = next(line for line in lines if "Ref" in line and "Fingerprint" in line)
    assert "Audit" in header

    bad_line = next(line for line in lines if "ADMIN_BAD" in line)
    assert "compromised" in bad_line

    ok_line = next(line for line in lines if "ADMIN_OK" in line)
    assert "clean" in ok_line
    assert "compromised" not in ok_line

    assert not _BASE64_KEY_RE.search(result.stderr)


def test_admin_list_with_unregistered_template_ref_exits_two(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["NOPE"]))
    result = invoke(runner, ["admin", "list"], env)
    assert result.exit_code == 2
    assert "missing" in result.stderr.lower()
