"""Tests for meshprovision.errors."""

from __future__ import annotations

import pytest

from meshprovision.errors import (
    MAX_ADMIN_KEYS,
    AdminRefUnresolvedError,
    ConfigError,
    CryptoError,
    DataSourceError,
    DbError,
    ExitCode,
    MeshprovisionError,
    MissingContactError,
    NamePatternError,
    NodeIdError,
    ProvisioningError,
    WeakKeyError,
    WriteVerificationError,
    exit_code_for,
)

pytestmark = pytest.mark.unit


def test_exit_code_values_are_pinned() -> None:
    assert ExitCode.OK.value == 0
    assert ExitCode.ERROR.value == 1
    assert ExitCode.CONFIG.value == 2
    assert ExitCode.DATASOURCE.value == 3
    assert ExitCode.DB.value == 4
    assert ExitCode.PROVISIONING.value == 5
    assert ExitCode.CRYPTO.value == 6
    assert ExitCode.STATUS_DEGRADED.value == 7
    assert ExitCode.INTERRUPTED.value == 130


def test_branch_exit_codes() -> None:
    assert ConfigError("x").exit_code == ExitCode.CONFIG
    assert DataSourceError("x").exit_code == ExitCode.DATASOURCE
    assert DbError("x").exit_code == ExitCode.DB
    assert ProvisioningError("x").exit_code == ExitCode.PROVISIONING
    assert CryptoError("x").exit_code == ExitCode.CRYPTO


def test_exit_code_for_meshprovision_error_subclass() -> None:
    assert exit_code_for(ConfigError("x")) == int(ExitCode.CONFIG)
    assert exit_code_for(CryptoError("x")) == int(ExitCode.CRYPTO)


def test_exit_code_for_keyboard_interrupt() -> None:
    assert exit_code_for(KeyboardInterrupt()) == int(ExitCode.INTERRUPTED)


def test_exit_code_for_system_exit_int_code() -> None:
    assert exit_code_for(SystemExit(3)) == 3


def test_exit_code_for_system_exit_str_code() -> None:
    assert exit_code_for(SystemExit("msg")) == 1


def test_exit_code_for_plain_value_error() -> None:
    assert exit_code_for(ValueError("boom")) == int(ExitCode.ERROR)


def test_user_message_with_and_without_hint() -> None:
    plain = MeshprovisionError("something broke")
    assert plain.user_message == "something broke"
    assert str(plain) == "something broke"

    hinted = MeshprovisionError("something broke", hint="try again")
    assert hinted.user_message == "something broke\nHint: try again"
    assert str(hinted) == "something broke"
    assert "try again" not in str(hinted)


def test_admin_ref_unresolved_default_hint_names_both_bootstrap_commands() -> None:
    exc = AdminRefUnresolvedError("unresolved", ref="ADMIN1")
    assert exc.hint is not None
    assert "mesh admin bootstrap" in exc.hint
    assert "mesh admin import" in exc.hint
    assert exc.ref == "ADMIN1"


def test_missing_contact_default_message_and_hint() -> None:
    exc = MissingContactError()
    assert "MESHPROVISION_CONTACT" in exc.message
    assert exc.hint is not None
    assert "MESHPROVISION_CONTACT" in exc.hint


def test_weak_key_error_attribute_plumbing() -> None:
    exc = WeakKeyError(
        "weak",
        reason="all zero",
        node_id="!deadbe01",
        key_ref="deadbe01_pub",
        severity="warning",
        fingerprint="sha256:ab12",
    )
    assert exc.reason == "all zero"
    assert exc.node_id == "!deadbe01"
    assert exc.key_ref == "deadbe01_pub"
    assert exc.severity == "warning"
    assert exc.fingerprint == "sha256:ab12"


def test_write_verification_error_attribute_plumbing() -> None:
    exc = WriteVerificationError(
        "mismatch",
        section="security",
        field="public_key",
        expected="<redacted>",
        actual="<redacted>",
    )
    assert exc.section == "security"
    assert exc.field == "public_key"
    assert exc.expected == "<redacted>"
    assert exc.actual == "<redacted>"


def test_db_validation_error_attribute_plumbing() -> None:
    from meshprovision.errors import DbValidationError

    exc = DbValidationError("bad", sheet="Nodes", row=3, column="role", value="XX")
    assert exc.sheet == "Nodes"
    assert exc.row == 3
    assert exc.column == "role"
    assert exc.value == "XX"


def test_name_pattern_error_attribute_plumbing() -> None:
    exc = NamePatternError(
        "too long",
        pattern="MT{n}{n}",
        rendered="MTZZ",
        byte_length=4,
        limit=4,
        field="short_name_pattern",
    )
    assert exc.pattern == "MT{n}{n}"
    assert exc.rendered == "MTZZ"
    assert exc.byte_length == 4
    assert exc.limit == 4
    assert exc.field == "short_name_pattern"


def test_node_id_error_carries_raw_value() -> None:
    exc = NodeIdError("bad", raw="garbage")
    assert exc.raw == "garbage"


def test_max_admin_keys() -> None:
    assert MAX_ADMIN_KEYS == 3
