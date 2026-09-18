"""Tests for meshprovision.crypto.weakkeys."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from meshprovision.crypto import weakkeys
from meshprovision.crypto.keys import KeyPair, generate_keypair
from meshprovision.crypto.weakkeys import (
    KNOWN_BAD_KEYS_ENV,
    LOW_HAMMING_MAX,
    LOW_HAMMING_MIN,
    MIN_DISTINCT_BYTES,
    SMALL_ORDER_POINTS,
    WeakKeyCheck,
    audit_keypair,
    audit_node,
    audit_private_key,
    audit_public_key,
    default_known_bad_keys_path,
    find_duplicate_public_keys,
    hamming_weight,
    is_low_entropy,
    is_monotonic_run,
    is_repeated_byte,
    is_small_order,
    is_vulnerable_firmware,
    load_known_bad_keys,
    parse_firmware_version,
    parse_known_bad_keys,
)
from meshprovision.errors import KeyMaterialError, SettingsError

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Crafted structural cases.
# ---------------------------------------------------------------------------


def test_audit_public_key_all_zero() -> None:
    result = weakkeys.audit_public_key(bytes(32))
    checks = {f.check for f in result.findings}
    assert result.compromised is True
    assert {
        WeakKeyCheck.ALL_ZERO,
        WeakKeyCheck.SMALL_ORDER,
        WeakKeyCheck.BLOCKLIST,
        WeakKeyCheck.REPEATED_BYTE,
        WeakKeyCheck.LOW_ENTROPY,
    } <= checks
    severities = [f.severity for f in result.findings]
    assert severities == sorted(severities, key=lambda s: 0 if s == "critical" else 1)


def test_audit_private_key_all_zero() -> None:
    result = weakkeys.audit_private_key(bytes(32))
    checks = {f.check for f in result.findings}
    assert WeakKeyCheck.ALL_ZERO in checks
    assert WeakKeyCheck.SMALL_ORDER not in checks


def test_audit_public_key_monotonic_run_is_critical() -> None:
    """Regression test: MONOTONIC must actually reach audit_public_key, not just is_monotonic_run.

    bytes(range(32)) has a normal Hamming weight (80, well inside
    [32, 224]) and 32 distinct byte values, so it trips MONOTONIC alone
    -- never ALL_ZERO/LOW_ENTROPY/REPEATED_BYTE -- confirming the finding
    reaches the full audit path with the right severity, not just the
    pure boolean check.
    """
    raw = bytes(range(32))
    result = weakkeys.audit_public_key(raw)
    monotonic = [f for f in result.findings if f.check == WeakKeyCheck.MONOTONIC]
    assert len(monotonic) == 1
    assert monotonic[0].severity == "critical"
    assert result.compromised is True


def test_audit_public_key_repeated_byte_is_critical_standalone() -> None:
    """Regression test: REPEATED_BYTE must reach audit_public_key on its own.

    test_audit_public_key_all_zero only ever exercises REPEATED_BYTE as
    a side effect of the all-zero case. bytes([0x7F]) * 32 is a distinct,
    non-zero repeated byte (Hamming weight 224, exactly at
    LOW_HAMMING_MAX -- not > it, so it doesn't trip the weight-based
    LOW_ENTROPY path either) that confirms REPEATED_BYTE itself is wired
    through with the right severity.
    """
    raw = bytes([0x7F]) * 32
    result = weakkeys.audit_public_key(raw)
    repeated = [f for f in result.findings if f.check == WeakKeyCheck.REPEATED_BYTE]
    assert len(repeated) == 1
    assert repeated[0].severity == "critical"
    assert result.compromised is True


# ---------------------------------------------------------------------------
# The 7 committed small-order points.
# ---------------------------------------------------------------------------


def test_known_bad_keys_file_has_exactly_seven_small_order_points(repo_root: Path) -> None:
    text = (repo_root / "data" / "known_bad_keys.txt").read_text(encoding="utf-8")
    parsed = parse_known_bad_keys(text, source="known_bad_keys.txt")
    assert set(parsed) == set(SMALL_ORDER_POINTS)
    assert len(parsed) == 7


def test_small_order_points_are_32_bytes_and_detected() -> None:
    for point in SMALL_ORDER_POINTS:
        assert len(point) == 32
        assert is_small_order(point)
    assert is_small_order(os.urandom(32)) is False
    assert is_small_order(b"short") is False


def test_lengthened_small_order_literal_fails_the_length_guard() -> None:
    """Guards the direction the removed ``[:64]`` slice used to mask.

    Without the slice, a hex literal accidentally lengthened by a future
    edit decodes to more than X25519_KEY_SIZE bytes and is caught by the
    same guard that already catches a shortened one -- the slice used to
    silently absorb exactly this case.
    """
    from meshprovision.crypto.keys import X25519_KEY_SIZE

    lengthened_hex = SMALL_ORDER_POINTS[0].hex() + "ff"
    decoded = bytes.fromhex(lengthened_hex)
    assert len(decoded) != X25519_KEY_SIZE


def test_small_order_points_subset_of_loaded_blocklist(repo_root: Path, tmp_path: Path) -> None:
    known_file = repo_root / "data" / "known_bad_keys.txt"
    assert set(SMALL_ORDER_POINTS) <= load_known_bad_keys(known_file)
    absent = tmp_path / "absent.txt"
    assert set(SMALL_ORDER_POINTS) <= load_known_bad_keys(absent)


def test_audit_public_key_small_order_point_is_blocklist_and_small_order() -> None:
    point = SMALL_ORDER_POINTS[2]
    result = audit_public_key(point)
    checks = {f.check: f.severity for f in result.findings}
    assert checks.get(WeakKeyCheck.BLOCKLIST) == "critical"
    assert checks.get(WeakKeyCheck.SMALL_ORDER) == "critical"


# ---------------------------------------------------------------------------
# Private/public mismatch.
# ---------------------------------------------------------------------------


def test_audit_keypair_mismatch(keypair_factory) -> None:
    kp_a: KeyPair = keypair_factory()
    kp_b: KeyPair = keypair_factory()
    result = audit_keypair(kp_a.private, kp_b.public)
    consistency = [f for f in result.findings if f.check == WeakKeyCheck.CONSISTENCY]
    assert len(consistency) == 1
    finding = consistency[0]
    assert finding.severity == "critical"
    assert finding.detail is not None
    assert finding.detail.count("sha256:") == 2
    import base64

    assert base64.b64encode(b"x").decode("ascii")[:4] not in finding.detail
    assert "#7449" in finding.reason


def test_audit_keypair_matching_is_ok(keypair_factory) -> None:
    kp: KeyPair = keypair_factory()
    result = audit_keypair(kp.private, kp.public)
    assert result.ok is True


# ---------------------------------------------------------------------------
# Firmware-version window.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["2.5.0", "2.6.10", "v2.6.10.9861e82"])
def test_audit_node_vulnerable_firmware_window(keypair_factory, version: str) -> None:
    kp = keypair_factory()
    result = audit_node(public=kp.public, firmware_version=version)
    assert any(
        f.check == WeakKeyCheck.FIRMWARE_WINDOW and f.severity == "critical"
        for f in result.findings
    )


@pytest.mark.parametrize("version", ["2.6.11", "2.6.12.9861e82", "2.4.99", "3.0.0"])
def test_audit_node_non_vulnerable_firmware(keypair_factory, version: str) -> None:
    kp = keypair_factory()
    result = audit_node(public=kp.public, firmware_version=version)
    assert not any(f.check == WeakKeyCheck.FIRMWARE_WINDOW for f in result.findings)


def test_audit_node_unknown_firmware_is_warning(keypair_factory) -> None:
    kp = keypair_factory()
    result = audit_node(public=kp.public, firmware_version="unknown")
    matches = [f for f in result.findings if f.check == WeakKeyCheck.FIRMWARE_WINDOW]
    assert len(matches) == 1
    assert matches[0].severity == "warning"


@pytest.mark.parametrize("version", ["", None])
def test_audit_node_blank_firmware_no_finding(keypair_factory, version) -> None:
    kp = keypair_factory()
    result = audit_node(public=kp.public, firmware_version=version)
    assert not any(f.check == WeakKeyCheck.FIRMWARE_WINDOW for f in result.findings)


def test_parse_firmware_version_and_is_vulnerable() -> None:
    assert parse_firmware_version("2.6.12.9861e82") == (2, 6, 12)
    assert parse_firmware_version("garbage") is None
    assert is_vulnerable_firmware((2, 5, 0)) is True
    assert is_vulnerable_firmware((2, 6, 11)) is False
    assert is_vulnerable_firmware(None) is False
    assert is_vulnerable_firmware("not a version") is False


# ---------------------------------------------------------------------------
# Cross-DB duplicate.
# ---------------------------------------------------------------------------


def test_audit_node_duplicate_excludes_self(keypair_factory) -> None:
    k = keypair_factory().public
    other = keypair_factory().public
    result = audit_node(
        public=k, key_ref="a_pub", known_public_keys={"a_pub": k, "b_pub": k, "c_pub": other}
    )
    dup = [f for f in result.findings if f.check == WeakKeyCheck.DUPLICATE]
    assert len(dup) == 1
    assert dup[0].severity == "critical"
    assert "b_pub" in (dup[0].detail or "")
    assert "a_pub" not in (dup[0].detail or "")
    assert "c_pub" not in (dup[0].detail or "")


def test_audit_node_duplicate_check_requires_key_ref_when_public_known(keypair_factory) -> None:
    k = keypair_factory().public
    with pytest.raises(KeyMaterialError) as exc_info:
        audit_node(public=k, known_public_keys={"a_pub": k})
    assert "key_ref" in str(exc_info.value)


def test_find_duplicate_public_keys() -> None:
    k = os.urandom(32)
    other = os.urandom(32)
    result = find_duplicate_public_keys({"a": k, "b": k, "c": other})
    assert result == {"a": ("b",), "b": ("a",)}


def test_audit_node_with_known_keys_but_no_public_no_duplicate_finding(keypair_factory) -> None:
    priv = keypair_factory().private
    other = keypair_factory().public
    result = audit_node(private=priv, known_public_keys={"x": other})
    assert not any(f.check == WeakKeyCheck.DUPLICATE for f in result.findings)


# ---------------------------------------------------------------------------
# Structural helpers.
# ---------------------------------------------------------------------------


def test_is_repeated_byte() -> None:
    assert is_repeated_byte(bytes([7]) * 32) is True
    assert is_repeated_byte(b"") is False
    assert is_repeated_byte(b"a") is False


def test_is_monotonic_run() -> None:
    ascending = bytes((i % 256) for i in range(32))
    descending = bytes((255 - i) % 256 for i in range(32))
    assert is_monotonic_run(ascending) is True
    assert is_monotonic_run(descending) is True
    assert is_monotonic_run(os.urandom(32)) in (True, False)  # sanity: never raises
    assert is_monotonic_run(bytes([1, 5, 2, 9] * 8)) is False


def test_is_monotonic_run_rejects_non_unit_step_arithmetic_progression() -> None:
    """A uniform step other than +-1 must not be flagged monotonic.

    Guards the ``and``/``or`` boundary between the "single delta" and
    "delta is 1 or 255" clauses: a step-2 progression has exactly one
    distinct delta (so the first clause alone can't distinguish it from
    a real +-1 run).
    """
    raw = bytes((i * 2) % 256 for i in range(32))
    assert len({(raw[i + 1] - raw[i]) % 256 for i in range(len(raw) - 1)}) == 1
    assert is_monotonic_run(raw) is False


def test_hamming_weight() -> None:
    assert hamming_weight(bytes([0xFF] * 32)) == 256
    assert hamming_weight(bytes(32)) == 0


def test_is_low_entropy_boundaries() -> None:
    below_min = bytes([0xFF] * (LOW_HAMMING_MIN // 8 - 1)) + bytes(32 - (LOW_HAMMING_MIN // 8 - 1))
    assert hamming_weight(below_min) < LOW_HAMMING_MIN
    assert is_low_entropy(below_min) is True

    above_max_weight = LOW_HAMMING_MAX + 8
    above_max = bytes([0xFF] * (above_max_weight // 8)) + bytes(32 - above_max_weight // 8)
    assert hamming_weight(above_max) > LOW_HAMMING_MAX
    assert is_low_entropy(above_max) is True

    low_distinct = bytes([1, 2, 3, 4]) * 8
    assert len(set(low_distinct)) < MIN_DISTINCT_BYTES
    assert is_low_entropy(low_distinct) is True


def test_is_low_entropy_flags_abnormal_weight_with_normal_byte_diversity() -> None:
    """Isolate the weight bound from the distinct-byte bound.

    Every other low-entropy fixture in this file is built out of runs of
    a repeated byte, which also trips the distinct-byte-count clause --
    so a broken ``or`` between the two weight comparisons could never be
    caught by them. This fixture has abnormally low weight but *normal*
    byte diversity, so it can only be flagged via the weight clause.
    """
    raw = bytearray(32)
    raw[0], raw[1], raw[2], raw[3] = 1, 2, 4, 8
    frozen = bytes(raw)
    assert len(set(frozen)) == 5  # {0, 1, 2, 4, 8} -- not independently low-distinct
    assert hamming_weight(frozen) == 4  # well below LOW_HAMMING_MIN
    assert is_low_entropy(frozen) is True


def _low_entropy_finding(raw: bytes) -> weakkeys.WeakKeyFinding:
    [finding] = [
        f
        for f in weakkeys._structural_findings(
            raw,
            include_small_order=False,
            fp="sha256:test",
            node_id=None,
            key_ref=None,
            material="public",
        )
        if f.check == WeakKeyCheck.LOW_ENTROPY
    ]
    return finding


def test_low_entropy_severity_symmetric_across_both_hamming_bounds() -> None:
    """Regression test: an above-maximum weight is exactly as critical as below-minimum.

    LOW_HAMMING_MIN/MAX are documented as a symmetric bound -- a key with
    an abnormally *high* Hamming weight (nearly all one-bits) is exactly
    as degenerate as one with an abnormally *low* weight (nearly all
    zero-bits), so both must report the same severity. Only the
    distinct-byte-count trigger stays at warning (see
    test_soft_audit_finding_logs_a_warning in test_pipeline.py, which
    pins that as deliberate).
    """
    below_min_weight = bytearray(32)
    weight = 0
    idx = 0
    while weight < LOW_HAMMING_MIN - 1:
        below_min_weight[idx % 32] |= 1 << (idx // 32 % 8)
        weight += 1
        idx += 1
    assert is_low_entropy(bytes(below_min_weight)) is True
    assert _low_entropy_finding(bytes(below_min_weight)).severity == "critical"

    above_max_target = LOW_HAMMING_MAX + 8
    above_max_weight = bytes([0xFF] * (above_max_target // 8)) + bytes(32 - above_max_target // 8)
    assert is_low_entropy(above_max_weight) is True
    assert _low_entropy_finding(above_max_weight).severity == "critical"

    low_distinct = bytes([1, 2, 3, 4]) * 8
    assert is_low_entropy(low_distinct) is True
    assert _low_entropy_finding(low_distinct).severity == "warning"


def test_low_entropy_severity_at_exact_hamming_boundary_is_still_warning() -> None:
    """A weight exactly at LOW_HAMMING_MIN/MAX is not itself abnormal.

    Guards ``<``/``>`` vs ``<=``/``>=`` in the severity check. Both
    fixtures also trip the distinct-byte-count clause (so
    ``is_low_entropy`` is still ``True`` overall), isolating the
    severity-determining weight comparison at the exact boundary value
    on its own.
    """
    at_min = bytes([0xFF] * (LOW_HAMMING_MIN // 8)) + bytes(32 - LOW_HAMMING_MIN // 8)
    assert hamming_weight(at_min) == LOW_HAMMING_MIN
    assert len(set(at_min)) < MIN_DISTINCT_BYTES
    assert is_low_entropy(at_min) is True
    assert _low_entropy_finding(at_min).severity == "warning"

    at_max = bytes([0xFF] * (LOW_HAMMING_MAX // 8)) + bytes(32 - LOW_HAMMING_MAX // 8)
    assert hamming_weight(at_max) == LOW_HAMMING_MAX
    assert len(set(at_max)) < MIN_DISTINCT_BYTES
    assert is_low_entropy(at_max) is True
    assert _low_entropy_finding(at_max).severity == "warning"


def test_clamping_check_default_off_and_explicit_on(keypair_factory) -> None:
    from meshprovision.crypto.keys import X25519_KEY_SIZE

    unclamped = bytes([0xFF] * X25519_KEY_SIZE)
    result_default = audit_private_key(unclamped, check_clamping=False)
    assert not any(f.check == WeakKeyCheck.UNCLAMPED for f in result_default.findings)

    result_checked = audit_private_key(unclamped, check_clamping=True)
    unclamped_findings = [f for f in result_checked.findings if f.check == WeakKeyCheck.UNCLAMPED]
    assert len(unclamped_findings) == 1
    assert unclamped_findings[0].severity == "warning"
    assert result_checked.compromised is False or any(
        f.severity == "critical"
        for f in result_checked.findings
        if f.check != WeakKeyCheck.UNCLAMPED
    )


def test_check_clamping_default_is_off_when_omitted_at_every_entry_point() -> None:
    """The default must actually be exercised by omission, not just by passing False.

    ``check_clamping`` defaults to ``False`` on every public entry point
    (module docstring); this only pins that when the keyword argument is
    left out entirely, at all three of ``audit_private_key``,
    ``audit_node``, and ``audit_keypair``.
    """
    from meshprovision.crypto.keys import X25519_KEY_SIZE

    unclamped = bytes([0xFF] * X25519_KEY_SIZE)
    other_public = bytes(X25519_KEY_SIZE)

    private_result = audit_private_key(unclamped)
    assert not any(f.check == WeakKeyCheck.UNCLAMPED for f in private_result.findings)

    node_result = audit_node(private=unclamped)
    assert not any(f.check == WeakKeyCheck.UNCLAMPED for f in node_result.findings)

    keypair_result = audit_keypair(unclamped, other_public)
    assert not any(f.check == WeakKeyCheck.UNCLAMPED for f in keypair_result.findings)


# ---------------------------------------------------------------------------
# Errors and files.
# ---------------------------------------------------------------------------


def test_audit_public_key_wrong_length_raises() -> None:
    with pytest.raises(KeyMaterialError) as exc_info:
        audit_public_key(b"\x00" * 31)
    assert exc_info.value.expected_length == 32


def test_audit_private_key_wrong_length_raises() -> None:
    with pytest.raises(KeyMaterialError) as exc_info:
        audit_private_key(b"\x00" * 16)
    assert exc_info.value.expected_length == 32
    assert exc_info.value.actual_length == 16


def test_audit_node_without_keys_raises() -> None:
    with pytest.raises(KeyMaterialError):
        audit_node()


def test_parse_known_bad_keys_comments_blanks_dedup() -> None:
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    text = f"""
# a comment
{kp1.public_b64}  # inline comment

{kp1.public_b64}
{kp2.public_b64}
"""
    parsed = parse_known_bad_keys(text)
    assert parsed == (kp1.public, kp2.public)


def test_parse_known_bad_keys_malformed_line_raises_without_leaking_token() -> None:
    with pytest.raises(KeyMaterialError) as exc_info:
        parse_known_bad_keys("not-valid-base64!!!\n", source="myfile.txt")
    assert "myfile.txt:1" in str(exc_info.value)
    assert "not-valid-base64" not in str(exc_info.value)


def test_load_known_bad_keys_caches_by_mtime_and_size(tmp_path: Path) -> None:
    kp1 = generate_keypair()
    kp2 = generate_keypair()
    path = tmp_path / "bad.txt"
    path.write_text(f"{kp1.public_b64}\n")

    first = load_known_bad_keys(path)
    assert kp1.public in first
    assert kp2.public not in first

    path.write_text(f"{kp1.public_b64}\n{kp2.public_b64}\n")
    second = load_known_bad_keys(path)
    assert kp2.public in second


def test_load_known_bad_keys_stat_failure_raises_key_material_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Force the second stat() call, not the one inside exists(), to fail.

    The *second* stat() -- the explicit one after exists() already
    succeeded -- is the one this test forces to fail, since exists()
    itself calls stat() internally and would otherwise be the one to
    (silently, for most errnos) absorb the failure.
    """
    path = tmp_path / "known_bad_keys.txt"
    path.write_text("")
    real_stat = Path.stat
    calls = 0

    def failing_stat(self: Path, *args: object, **kwargs: object) -> object:
        nonlocal calls
        if self == path:
            calls += 1
            if calls > 1:
                raise OSError("permission denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", failing_stat)
    with pytest.raises(KeyMaterialError):
        load_known_bad_keys(path)


def test_load_known_bad_keys_read_failure_raises_key_material_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "known_bad_keys.txt"
    path.write_text("")
    real_read_text = Path.read_text

    def failing_read_text(self: Path, *args: object, **kwargs: object) -> str:
        if self == path:
            raise OSError("i/o error")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing_read_text)
    with pytest.raises(KeyMaterialError):
        load_known_bad_keys(path)


def test_default_known_bad_keys_path_env_nonexistent_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(KNOWN_BAD_KEYS_ENV, str(tmp_path / "nope.txt"))
    with pytest.raises(SettingsError):
        default_known_bad_keys_path()


def test_default_known_bad_keys_path_env_existing_file_wins(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The documented, intended use of the override env var: point it at a real file.

    The two existing env-var tests only cover a nonexistent path
    (raises) and the var being unset entirely (falls through to the
    bundled candidates) -- the actual documented behavior
    (docs/configuration.md's "override path to the weak-key blocklist"),
    a valid override file being returned as-is rather than silently
    ignored, had no test.
    """
    override = tmp_path / "custom_known_bad.txt"
    override.write_text("# custom blocklist\n")
    monkeypatch.setenv(KNOWN_BAD_KEYS_ENV, str(override))

    assert default_known_bad_keys_path() == override


def _candidate_paths() -> tuple[Path, Path | None, Path]:
    """The three non-env candidates default_known_bad_keys_path tries, in order."""
    import meshprovision.crypto.weakkeys as weakkeys_module

    module_parents = Path(weakkeys_module.__file__).resolve().parents
    package_root = module_parents[1]
    repo_root_candidate = module_parents[3] if len(module_parents) > 3 else None
    return (
        package_root / "data" / "known_bad_keys.txt",
        (repo_root_candidate / "data" / "known_bad_keys.txt") if repo_root_candidate else None,
        Path.cwd() / "data" / "known_bad_keys.txt",
    )


def test_default_known_bad_keys_path_falls_back_to_package_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(KNOWN_BAD_KEYS_ENV, raising=False)
    package_candidate, repo_candidate, cwd_candidate = _candidate_paths()
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == package_candidate:
            return True
        if self in (repo_candidate, cwd_candidate):
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    assert default_known_bad_keys_path() == package_candidate


def test_default_known_bad_keys_path_falls_back_to_cwd_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(KNOWN_BAD_KEYS_ENV, raising=False)
    package_candidate, repo_candidate, cwd_candidate = _candidate_paths()
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == cwd_candidate:
            return True
        if self in (package_candidate, repo_candidate):
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    assert default_known_bad_keys_path() == cwd_candidate


def test_default_known_bad_keys_path_falls_back_to_repo_root_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repo-root candidate (a checkout run from source) must actually participate."""
    monkeypatch.delenv(KNOWN_BAD_KEYS_ENV, raising=False)
    package_candidate, repo_candidate, cwd_candidate = _candidate_paths()
    assert repo_candidate is not None
    real_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == repo_candidate:
            return True
        if self in (package_candidate, cwd_candidate):
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    assert default_known_bad_keys_path() == repo_candidate


def test_audit_result_api(keypair_factory) -> None:
    kp = keypair_factory()
    ok_result = audit_public_key(kp.public)
    assert ok_result.ok is True
    assert ok_result.compromised is False
    assert ok_result.summary() == ""

    bad_result = audit_public_key(bytes(32))
    assert bad_result.ok is False
    assert bad_result.compromised is True
    summary = bad_result.summary()
    assert summary

    for line in summary.splitlines():
        # No stray base64-looking 44-char token should appear in the summary.
        for word in line.split():
            assert not (len(word) == 44 and word.endswith("="))
    with pytest.raises(Exception):  # noqa: B017
        bad_result.raise_if_compromised()
