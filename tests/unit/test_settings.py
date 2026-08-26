"""Tests for meshprovision.config.settings."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from meshprovision.config.settings import (
    DEFAULT_CACHE_TTL,
    Settings,
    find_env_file,
    format_validation_error,
    load_settings,
)
from meshprovision.errors import MissingContactError, SettingsError

pytestmark = pytest.mark.unit


def test_load_settings_from_env_file_alone(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=me@example.invalid\nMESHPROVISION_LOG_LEVEL=DEBUG\n")
    settings = load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert settings.contact == "me@example.invalid"
    assert settings.log_level == "DEBUG"


def test_environ_overrides_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=fromfile@example.invalid\n")
    settings = load_settings(
        env_file=env_file, environ={"MESHPROVISION_CONTACT": "fromenv@example.invalid"}
    )
    assert settings.contact == "fromenv@example.invalid"


def test_overrides_beat_both(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=fromfile@example.invalid\n")
    settings = load_settings(
        env_file=env_file,
        environ={"MESHPROVISION_CONTACT": "fromenv@example.invalid"},
        overrides={"contact": "fromoverride@example.invalid"},
    )
    assert settings.contact == "fromoverride@example.invalid"


def test_blank_value_treated_as_unset(tmp_path: Path) -> None:
    settings = load_settings(environ={"MESHPROVISION_CONTACT": "   "}, search_dotenv=False)
    assert settings.contact is None


def test_os_environ_never_mutated(tmp_path: Path) -> None:
    snapshot = dict(os.environ)
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=me@example.invalid\n")
    load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert os.environ == snapshot


def test_invalid_cache_ttl_raises_and_does_not_echo_value() -> None:
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={"MESHPROVISION_CACHE_TTL": "-5"}, search_dotenv=False)
    assert "-5" not in str(exc_info.value)


def test_require_contact_raises_when_unset() -> None:
    settings = Settings(contact=None)
    with pytest.raises(MissingContactError):
        settings.require_contact()


def test_require_contact_whitespace_only_is_unset() -> None:
    settings = Settings.model_validate({"contact": "   "})
    with pytest.raises(MissingContactError):
        settings.require_contact()


def test_user_agent_format() -> None:
    settings = Settings(contact="me@example.invalid")
    agent = settings.user_agent(version="9.9.9")
    assert agent == "meshprovision/9.9.9 (+me@example.invalid)"


def test_user_agent_omits_contact_when_not_required_and_unset() -> None:
    settings = Settings(contact=None)
    assert settings.user_agent(version="9.9.9", require_contact=False) == "meshprovision/9.9.9"


def test_user_agent_still_includes_contact_when_set_and_not_required() -> None:
    settings = Settings(contact="me@example.invalid")
    agent = settings.user_agent(version="9.9.9", require_contact=False)
    assert agent == "meshprovision/9.9.9 (+me@example.invalid)"


def test_with_overrides_returns_new_revalidated_instance() -> None:
    settings = Settings(contact="me@example.invalid")
    updated = settings.with_overrides(log_level="debug")
    assert updated is not settings
    assert updated.log_level == "DEBUG"
    assert settings.log_level == "INFO"


def test_tilde_expansion_on_path_fields(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = Settings.model_validate({"db_path": "~/mydb.ods"})
    assert str(settings.db_path) == str(tmp_path / "mydb.ods")


def test_find_env_file_walks_upward(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("X=1\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    found = find_env_file(nested)
    assert found == tmp_path / ".env"


def test_find_env_file_returns_none_when_absent(tmp_path: Path) -> None:
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_env_file(nested) is None


def test_format_validation_error_lists_field_paths_never_input() -> None:
    from pydantic import ValidationError

    try:
        Settings.model_validate({"cache_ttl": "not-a-number"})
    except ValidationError as exc:
        text = format_validation_error(exc, source="test-source")
        assert "test-source" in text
        assert "cache_ttl" in text
        assert "not-a-number" not in text
    else:
        pytest.fail("expected a ValidationError")


def test_default_cache_ttl_constant() -> None:
    assert DEFAULT_CACHE_TTL == 300.0
