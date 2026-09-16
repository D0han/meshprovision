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
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto import redact, weakkeys
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

    from meshprovision.crypto.keys import KeyPair
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


def test_admin_bootstrap_pending_message_names_the_right_ref_and_node_on_rotation(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """Rotating an existing admin ref must not conflate two distinct pending facts.

    Regression test for a bug in ``admin_bootstrap``'s pending-cross-
    authorization message: a second internal check-loop correctly
    detects that *this* newly-bootstrapped node doesn't yet authorize
    some *other* admin's ref, but the buggy code rendered that finding
    through the wrong (ref, node) pair -- reusing the just-bootstrapped
    ref's name paired with the *other* admin's own node, producing a
    false claim about a node that was already fully authorized. The
    original sequential-growth test above never rotates an existing
    ref, so it can't reach this path (see its module docstring).

    Setup (seeded directly, so the scenario doesn't depend on exactly
    which keypair a live ``mesh provision`` run happens to generate):
    ``aaaa0001`` is ADMIN1's own device (its identity key is filed both
    as ``aaaa0001_pub`` and, aliased, as ``ADMIN1_pub``) and already
    authorizes ``ADMIN2_pub``. ``ADMIN2_pub``/``ADMIN2_priv`` hold old,
    about-to-be-replaced material with no node of their own. ADMIN2 is
    then rotated onto a brand-new device ``aaaa0003``, using a template
    that does *not* list ADMIN1 -- so ``aaaa0003`` itself doesn't
    authorize ``ADMIN1_pub`` yet, even though ``aaaa0001`` already
    authorizes ``ADMIN2_pub``. The correct message is "authorize
    ADMIN1_pub on node aaaa0003"; the bug instead printed the false
    "authorize ADMIN2_pub on node aaaa0001".
    """
    admin1_kp = keypair_factory()
    old_admin2_kp = keypair_factory()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="aaaa0001",
                management=ManagementMode.TEMPLATE,
                authorized_admin_keys=("ADMIN2_pub",),
            ),
            # Authorizes ADMIN1_pub so ADMIN1 is discoverable via
            # collect_admins's extra_refs path (this run's own template
            # doesn't list ADMIN1, so template_refs alone won't surface it).
            NodeRecord(
                node_id="aaaa0002",
                management=ManagementMode.TEMPLATE,
                authorized_admin_keys=("ADMIN1_pub",),
            ),
        ],
        keys=[
            *KeyRecord.for_keypair("aaaa0001", admin1_kp),
            *KeyRecord.for_keypair("ADMIN1", admin1_kp),
            *KeyRecord.for_keypair("ADMIN2", old_admin2_kp),
        ],
    )

    # Rotate ADMIN2 onto a brand-new device; this run's own template omits
    # ADMIN1, so aaaa0003 itself won't authorize ADMIN1_pub.
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=[]))
    bus.use(FakeMeshInterface("aaaa0003"))
    result = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN2", "--yes"],
        env,
    )
    assert result.exit_code == 0

    assert "pending: authorize ADMIN1_pub on node aaaa0003" in result.stderr
    assert "pending: authorize ADMIN2_pub on node aaaa0001" not in result.stderr


def test_admin_bootstrap_pending_message_for_its_own_ref_names_ref_first_then_node(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """The just-bootstrapped ref's own pending list must render (ref, node), not (node, ref).

    Regression guard distinct from the rotation test above: that one only
    exercises the *second* comprehension's pending pair (some other
    admin's ref pending on this node). This one targets the *first*
    comprehension -- ``new_summary.pending_on``, i.e. nodes that still
    need *this* bootstrap's own ref authorized on them -- which a tuple-
    order swap (``(other_hex, new_ref)`` instead of ``(new_ref,
    other_hex)``) would corrupt into a nonsensical message without the
    rotation test noticing.
    """
    admin1_kp = keypair_factory()
    placeholder_admin2_kp = keypair_factory()
    seed_db(
        nodes=[
            # Owned by ADMIN1 (identity match) but does not yet authorize
            # ADMIN2_pub -- the node that should end up pending.
            NodeRecord(
                node_id="aaaa0001",
                management=ManagementMode.TEMPLATE,
                authorized_admin_keys=("ADMIN1_pub",),
            ),
            # Authorizes ADMIN2_pub already, purely so ADMIN2 is
            # discoverable via collect_admins's extra_refs path before its
            # own bootstrap below -- not itself owned by anyone.
            NodeRecord(
                node_id="bbbb0001",
                management=ManagementMode.TEMPLATE,
                authorized_admin_keys=("ADMIN2_pub",),
            ),
        ],
        keys=[
            *KeyRecord.for_keypair("aaaa0001", admin1_kp),
            *KeyRecord.for_keypair("ADMIN1", admin1_kp),
            *KeyRecord.for_keypair("ADMIN2", placeholder_admin2_kp),
        ],
    )
    bus.use(FakeMeshInterface("aaaa0002"))

    result = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN2", "--yes"],
        env,
    )

    assert result.exit_code == 0
    assert "pending: authorize ADMIN2_pub on node aaaa0001" in result.stderr
    assert "pending: authorize aaaa0001_pub on node ADMIN2" not in result.stderr


def test_admin_bootstrap_uncertain_outcome_skips_reporting_and_exits_nonzero(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    write_template: Callable[..., Path],
    seed_db: Callable[..., Path],
    keypair_factory: Callable[[], KeyPair],
) -> None:
    """A write-verify failure must skip the pending-report block and still exit non-zero.

    Regression guard for two structurally separate gaps: the ``if
    result.persisted:`` guard around the whole authorized/pending
    reporting block was never exercised with ``persisted=False`` (every
    other admin-bootstrap test either succeeds cleanly or fails via an
    exception raised earlier, e.g. the enroll gate, which never reaches
    this block at all) -- nor was the final ``if result.exit_code: raise
    SystemExit(...)``, specifically for ``admin bootstrap``.
    ``fail_reads_after_write`` produces exactly this: a normal return
    from ``run_provision`` with ``persisted=False`` and a nonzero exit
    code, not a raised exception.

    An existing admin (``EXISTING``, named in the template so the plan
    actually wants to authorize it here) is seeded so the guard's
    absence would be observable: ``result.plan`` is still populated on
    an uncertain outcome (the plan was built and attempted, just not
    confirmed), so ``authorized_here`` is non-empty regardless of
    ``persisted`` -- a template with nothing to authorize would make
    this test pass whether or not the guard fires at all.
    """
    existing_kp = keypair_factory()
    seed_db(
        nodes=[NodeRecord(node_id="aaaa0001", authorized_admin_keys=("EXISTING_pub",))],
        keys=list(KeyRecord.for_keypair("EXISTING", existing_kp)),
    )
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=["EXISTING"]))
    bus.use(FakeMeshInterface("deadbe01", fail_reads_after_write=True))

    result = invoke(
        runner, ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN1", "--yes"], env
    )

    assert result.exit_code != 0
    assert "UNCERTAIN" in result.stderr
    assert "Authorized on" not in result.stderr
    assert "pending:" not in result.stderr


def test_admin_bootstrap_json_output(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """``--json`` was never exercised for ``admin bootstrap`` by any existing test."""
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--ref", "ADMIN1", "--yes", "--json"],
        env,
    )

    assert result.exit_code == 0
    # run_provision itself also emits a detection/plan JSON document to
    # stdout when --json is set (printed before admin_bootstrap's own) --
    # split on the boundary between the two top-level documents and take
    # the last one, rather than assuming stdout holds a single object.
    documents = re.split(r"(?<=\})\n(?=\{)", result.stdout.strip())
    document = json.loads(documents[-1])
    assert document["node_id"] == "deadbe01"
    assert document["ref"] == "ADMIN1"
    assert document["authorized_on_this_node"] == []
    assert document["pending"] == []


def test_admin_bootstrap_inherits_the_enroll_gate(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    record = NodeRecord(node_id="deadbe01", management=ManagementMode.OBSERVED)
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "--enroll" in result.stderr


def test_admin_bootstrap_inherits_the_archived_gate(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, seed_db: Callable[..., Path]
) -> None:
    """admin_bootstrap reuses run_provision wholesale -- confirms it inherits this gate too."""
    record = NodeRecord(node_id="deadbe01", archived_at=datetime(2026, 1, 1, tzinfo=UTC))
    seed_db(nodes=[record])
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["admin", "bootstrap", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == int(ExitCode.PROVISIONING)
    assert "archived" in result.stderr.lower()


def test_admin_bootstrap_inherits_no_reconnect(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    """admin_bootstrap reuses run_provision wholesale -- confirms --no-reconnect is honored too.

    README documents that `admin bootstrap` "accepts and honors every
    option in `mesh provision`'s table," but no test exercised
    --no-reconnect/--allow-lockdown/--force-regenerate-key through
    bootstrap specifically until now. All three flow through the same
    ProvisionOptions construction, so proving the wiring for one
    (bus.connections is the same real discriminator used for
    provision's own --no-reconnect test) is strong evidence for the
    others sharing that exact code path.
    """
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        [
            "admin",
            "bootstrap",
            "--port",
            "/dev/ttyFAKE0",
            "--ref",
            "ADMIN1",
            "--yes",
            "--no-reconnect",
        ],
        env,
    )

    assert result.exit_code == 0
    assert "--no-reconnect" in result.stderr
    assert len(bus.connections) == 1


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


def test_admin_import_dry_run_reports_without_registering(
    runner: CliRunner, env: dict[str, str]
) -> None:
    """--dry-run must run every check (audit, dedup) but write nothing.

    admin_import previously had no way to preview a registration's
    outcome before committing it, unlike provision/adopt/admin bootstrap,
    which all support --dry-run.
    """
    kp = generate_keypair()

    result = invoke(
        runner, ["admin", "import", f"ADMIN9={kp.public_b64}", "--dry-run", "--json"], env
    )

    assert result.exit_code == 0
    assert "Would register" in result.stderr
    document = json.loads(result.stdout)
    assert document["dry_run"] is True
    assert document["registered"] == [
        {
            "ref": "ADMIN9",
            "key_ref": "ADMIN9_pub",
            "fingerprint": redact.fingerprint(kp.public),
        }
    ]

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert loaded.keys == ()


def test_admin_import_dry_run_still_refuses_a_weak_key(
    runner: CliRunner, env: dict[str, str]
) -> None:
    """--dry-run must still run the weak-key audit and refuse, not silently accept.

    Confirms --dry-run previews a *refusal* too, not just a success --
    the whole point is showing the operator what --force would actually
    need to override.
    """
    bad_b64 = base64.b64encode(weakkeys.SMALL_ORDER_POINTS[0]).decode("ascii")

    result = invoke(runner, ["admin", "import", f"ADMIN9={bad_b64}", "--dry-run"], env)

    assert result.exit_code != 0
    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert loaded.keys == ()


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


def test_admin_import_dry_run_catches_an_intra_batch_duplicate(
    runner: CliRunner, env: dict[str, str]
) -> None:
    """--dry-run must refuse the same duplicate a real run would refuse.

    A real run upserts each assignment into the in-memory session as it
    goes, so a later assignment in the same batch sees an earlier one's
    material via the dupe check's db.keys.public_key_map() read. Before
    this fix, --dry-run skipped that upsert entirely (gated on
    `not dry_run`), so two assignments sharing material in one --dry-run
    invocation never saw each other and both silently "passed" -- only
    for the real (non-dry-run) run of the exact same arguments to then
    abort partway through on the same duplicate.
    """
    kp = generate_keypair()

    dry_run_result = invoke(
        runner,
        ["admin", "import", f"ADMIN_A={kp.public_b64}", f"ADMIN_B={kp.public_b64}", "--dry-run"],
        env,
    )

    assert dry_run_result.exit_code != 0
    assert "already registered as ADMIN_A_pub" in dry_run_result.stderr

    loaded = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    assert loaded.keys == ()


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


def test_admin_import_leaves_a_node_with_no_unregistered_keys_completely_untouched(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """A node with no ``unregistered_admin_keys`` at all must not be rewritten.

    Regression guard for ``_drop_now_registered_key``'s ``if len(kept)
    != len(node.unregistered_admin_keys):`` guard: an unconditional
    upsert would rewrite every node's row (bumping ``last_updated_ts``)
    on every ``admin import``, even a node with nothing to drop. No
    existing test seeds a node untouched by the imported key to catch
    this.
    """
    adopted_kp = generate_keypair()
    seed_db(
        nodes=[
            NodeRecord(
                node_id="cafe0001", unregistered_admin_keys=(encode_key(adopted_kp.public),)
            ),
            NodeRecord(node_id="cafe0002"),
        ]
    )
    loaded_before = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    untouched_before = next(row for row in loaded_before.nodes if row["node_id"] == "cafe0002")

    result = invoke(runner, ["admin", "import", f"FRIEND={adopted_kp.public_b64}"], env)
    assert result.exit_code == 0

    loaded_after = ods.load_database(Path(env["MESHPROVISION_DB_PATH"]))
    untouched_after = next(row for row in loaded_after.nodes if row["node_id"] == "cafe0002")
    assert untouched_after == untouched_before


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
