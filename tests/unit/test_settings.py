"""Tests for meshprovision.config.settings."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from meshprovision.config.settings import (
    APP_NAME,
    DEFAULT_CACHE_TTL,
    PROCESS_ENV_ONLY,
    Settings,
    default_cache_dir,
    format_validation_error,
    load_settings,
)
from meshprovision.crypto.known_bad_keys import KNOWN_BAD_KEYS_ENV
from meshprovision.db.locking import LOCK_TIMEOUT_ENV
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


def test_unrecognized_env_var_from_environ_logs_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A typo'd MESHPROVISION_* variable must not be silently ignored.

    The field still falls back to its default either way -- this only
    pins that the operator gets a trail back to the cause.
    """
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(environ={"MESHPROVISION_CACHE_TLL": "600"}, search_dotenv=False)
    assert any("MESHPROVISION_CACHE_TLL" in r.getMessage() for r in caplog.records)


def test_unrecognized_env_var_from_dotenv_logs_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CACHE_TLL=600\n")
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert any("MESHPROVISION_CACHE_TLL" in r.getMessage() for r in caplog.records)


def test_recognized_env_vars_never_log_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(environ={"MESHPROVISION_CONTACT": "me@example.invalid"}, search_dotenv=False)
    assert caplog.records == []


def test_process_env_only_variables_do_not_warn_from_the_environment(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Read straight from ``os.environ`` by their own modules, so they are not "ignored"."""
    environ = {"MESHPROVISION_LOCK_TIMEOUT": "5", "MESHPROVISION_KNOWN_BAD_KEYS": "/x"}
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(environ=environ, search_dotenv=False)
    assert caplog.records == []


def test_process_env_only_variable_in_dotenv_warns_it_is_ignored(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_LOCK_TIMEOUT=5\n")
    with caplog.at_level("WARNING", logger="meshprovision.config.settings"):
        load_settings(env_file=env_file, environ={}, search_dotenv=False)
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1
    assert "MESHPROVISION_LOCK_TIMEOUT in .env is ignored" in messages[0]
    assert "process environment only" in messages[0]


def test_process_env_only_names_match_their_readers() -> None:
    assert frozenset({KNOWN_BAD_KEYS_ENV, LOCK_TIMEOUT_ENV}) == PROCESS_ENV_ONLY


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


def test_user_agent_requires_contact_by_default() -> None:
    """``require_contact`` defaults to True -- the lorastats.pl startup gate.

    Both real call sites pass the kwarg explicitly, and the one test that
    omits it already has ``contact`` set, so nothing else distinguishes
    the default from ``require_contact=False``.
    """
    settings = Settings(contact=None)
    with pytest.raises(MissingContactError):
        settings.user_agent(version="9.9.9")


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
    assert settings.log_level == "WARNING"


def test_tilde_expansion_on_path_fields(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = Settings.model_validate({"db_path": "~/mydb.ods"})
    assert str(settings.db_path) == str(tmp_path / "mydb.ods")


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


def test_default_cache_dir_is_app_scoped() -> None:
    cache_dir = default_cache_dir()
    assert cache_dir.name == APP_NAME
    assert cache_dir.is_absolute()


_ZACHOD_NFD = "Zacho\u0301d"


def test_lorastats_regions_splits_a_comma_separated_value_and_drops_blanks() -> None:
    settings = load_settings(
        environ={"MESHPROVISION_LORASTATS_REGIONS": f" {_ZACHOD_NFD} , PL ,, pl,PL"},
        search_dotenv=False,
    )
    assert settings.lorastats_regions == ("Zachód", "PL", "pl")


@pytest.mark.parametrize("raw", ["", " , ,", ","])
def test_lorastats_regions_without_a_name_is_unset(raw: str) -> None:
    settings = load_settings(environ={"MESHPROVISION_LORASTATS_REGIONS": raw}, search_dotenv=False)
    assert settings.lorastats_regions is None


def test_lorastats_regions_is_unset_by_default() -> None:
    assert load_settings(environ={}, search_dotenv=False).lorastats_regions is None


def test_lorastats_regions_is_read_from_a_dotenv_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_LORASTATS_REGIONS=Zachód,PL\n", encoding="utf-8")
    settings = load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert settings.lorastats_regions == ("Zachód", "PL")


def test_a_malformed_lorastats_region_fails_settings_validation() -> None:
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={"MESHPROVISION_LORASTATS_REGIONS": "PL,a/b"}, search_dotenv=False)
    assert "lorastats_regions" in exc_info.value.message


def test_lorastats_regions_rejects_a_non_string_entry() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings.model_validate({"lorastats_regions": ["PL", 1]})


def test_lorastats_regions_survive_with_overrides() -> None:
    settings = Settings.model_validate({"lorastats_regions": "Zachód,PL"})
    assert settings.with_overrides(log_level="debug").lorastats_regions == ("Zachód", "PL")


def test_the_bundled_env_example_names_every_settings_variable() -> None:
    from meshprovision.cli.setup import ENV_EXAMPLE_NAME, read_example_text
    from meshprovision.config.settings import ENV_FIELD_MAP

    text = read_example_text(ENV_EXAMPLE_NAME)
    assert [name for name in ENV_FIELD_MAP if name not in text] == []
