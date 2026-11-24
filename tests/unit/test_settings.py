"""Tests for meshprovision.config.settings."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from meshprovision.config.settings import (
    APP_NAME,
    DEFAULT_CACHE_TTL,
    FROM_ENVIRONMENT,
    PROCESS_ENV_ONLY,
    Settings,
    contact_problem,
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
    env_file.write_text(
        "MESHPROVISION_CONTACT=d0hanzibi+me@gmail.com\nMESHPROVISION_LOG_LEVEL=DEBUG\n"
    )
    settings = load_settings(env_file=env_file, environ={}, search_dotenv=False)
    assert settings.contact == "d0hanzibi+me@gmail.com"
    assert settings.log_level == "DEBUG"


def test_environ_overrides_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=d0hanzibi+fromfile@gmail.com\n")
    settings = load_settings(
        env_file=env_file, environ={"MESHPROVISION_CONTACT": "d0hanzibi+fromenv@gmail.com"}
    )
    assert settings.contact == "d0hanzibi+fromenv@gmail.com"


def test_overrides_beat_both(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=d0hanzibi+fromfile@gmail.com\n")
    settings = load_settings(
        env_file=env_file,
        environ={"MESHPROVISION_CONTACT": "d0hanzibi+fromenv@gmail.com"},
        overrides={"contact": "d0hanzibi+fromoverride@gmail.com"},
    )
    assert settings.contact == "d0hanzibi+fromoverride@gmail.com"


def test_blank_value_treated_as_unset(tmp_path: Path) -> None:
    settings = load_settings(environ={"MESHPROVISION_CONTACT": "   "}, search_dotenv=False)
    assert settings.contact is None


def test_os_environ_never_mutated(tmp_path: Path) -> None:
    snapshot = dict(os.environ)
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=d0hanzibi+me@gmail.com\n")
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
        load_settings(
            environ={"MESHPROVISION_CONTACT": "d0hanzibi+me@gmail.com"}, search_dotenv=False
        )
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


_PLACEHOLDER_CONTACTS = (
    "you@example.com",
    "ops@example.org",
    "ops@EXAMPLE.NET",
    "ops@mail.example.com",
    "me@site.example",
    "t@example.invalid",
    "a@b.test",
    "root@localhost",
    "root@localhost.",
    "Ops <ops@example.org>",
    "https://example.com/contact",
    "http://localhost:8080/",
)


@pytest.mark.parametrize("contact", _PLACEHOLDER_CONTACTS)
def test_contact_problem_names_a_reserved_domain(contact: str) -> None:
    problem = contact_problem(contact)
    assert problem is not None
    assert "placeholder" in problem


@pytest.mark.parametrize("contact", ["example", "ops at example dot org", "ftp://x.pl/"])
def test_contact_problem_wants_an_email_address_or_a_url(contact: str) -> None:
    assert contact_problem(contact) == (
        f"Contact '{contact}' is neither an email address nor an http(s):// URL."
    )


@pytest.mark.parametrize("contact", ["ops@", "https://", "http://[::1", "ops@.", "https://./"])
def test_contact_problem_wants_a_domain(contact: str) -> None:
    assert contact_problem(contact) == f"Contact '{contact}' has no valid domain."


@pytest.mark.parametrize(
    "contact",
    ["http://127.0.0.1", "https://[::1]/", "ops@[10.0.0.1]", "ops@[IPv6:fe80::1]", "a@[192.0.2.1]"],
)
def test_contact_problem_refuses_an_address_that_reaches_nobody(contact: str) -> None:
    assert contact_problem(contact) == (
        f"Contact '{contact}' names a loopback, private or reserved address, which reaches nobody."
    )


@pytest.mark.parametrize("contact", ["a@b", "https://intranet/", "ops@mailhost."])
def test_contact_problem_refuses_a_single_label_domain(contact: str) -> None:
    assert contact_problem(contact) == (
        f"Contact '{contact}' has a single-label domain, which reaches nobody."
    )


@pytest.mark.parametrize("contact", ["Paweł Nowak <pawel@wp.pl>", "kontakt@łódź.pl"])
def test_contact_problem_refuses_non_ascii_with_a_punycode_hint(contact: str) -> None:
    problem = contact_problem(contact)

    assert problem is not None
    assert problem.startswith(f"Contact '{contact}' has characters other than ASCII")
    assert "punycode (xn--...)" in problem


@pytest.mark.parametrize("contact", ["ops@x.pl\r\nX-Evil: 1", "ops@x.pl\x00", "ops@x\x7f.pl"])
def test_contact_problem_refuses_a_control_character_without_echoing_it(contact: str) -> None:
    assert contact_problem(contact) == (
        "Contact has a line break or other control character, which no header can carry."
    )


@pytest.mark.parametrize(
    "contact", ["me@gmail.com, https://site.org", "me@exa mple.org", "me@gmail.com;x", "me@x.pl ("]
)
def test_contact_problem_wants_only_a_domain_after_the_last_at_sign(contact: str) -> None:
    assert contact_problem(contact) == (
        f"Contact '{contact}': the text after the last '@' must be only a domain; "
        "add a name as `Name <me@host>`."
    )


@pytest.mark.parametrize(
    "contact", ["me@mesh.local", "me@x.internal", "me@router.home.arpa", "https://nas.local/"]
)
def test_contact_problem_refuses_a_local_only_domain(contact: str) -> None:
    problem = contact_problem(contact)

    assert problem is not None
    assert "placeholder" in problem


def test_contact_problem_takes_the_domain_after_the_last_at_sign() -> None:
    problem = contact_problem("ops@x@example.com")

    assert problem is not None
    assert "placeholder" in problem


@pytest.mark.parametrize(
    "contact",
    [
        "d0hanzibi+meshprovision-dev@gmail.com",
        "Jan <jan@mesh-example.pl>",
        "ops@examples.org",
        "ops@example.org.pl",
        "https://github.com/someone",
        "HTTPS://lorastats.pl/contact",
        "kontakt@xn--dz-fja.pl",
        "d0hanzibi+ops@gmail.com (Jan Kowalski)",
        "Jan <jan@mesh-example.pl> (ops)",
        "ops@[8.8.8.8]",
        "ops@[IPv6:2606:4700:4700::1111]",
        "https://[2606:4700:4700::1111]/",
    ],
)
def test_contact_problem_accepts_a_real_looking_contact(contact: str) -> None:
    assert contact_problem(contact) is None


@pytest.mark.parametrize("required", [True, False])
def test_user_agent_refuses_a_placeholder_contact(required: bool) -> None:
    settings = Settings(contact="you@example.com")
    with pytest.raises(SettingsError, match="placeholder") as exc_info:
        settings.user_agent(version="9.9.9", require_contact=required)
    assert exc_info.value.hint is not None
    assert "own email address" in exc_info.value.hint


def test_require_contact_refuses_a_placeholder_contact() -> None:
    with pytest.raises(SettingsError, match=r"^MESHPROVISION_CONTACT: Contact 'a@b\.test'"):
        Settings(contact="a@b.test").require_contact()


def test_a_contact_from_dotenv_is_fixed_in_that_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=you@example.com\n", encoding="utf-8")
    settings = load_settings(env_file=env_file, environ={}, search_dotenv=False)

    with pytest.raises(SettingsError) as exc_info:
        settings.require_contact()

    assert settings.contact_source == str(env_file.absolute())
    assert exc_info.value.hint is not None
    assert exc_info.value.hint.startswith(
        f"Set MESHPROVISION_CONTACT in {env_file.absolute()} to your own email address or URL."
    )


def test_a_contact_from_the_environment_overrides_dotenv_and_says_so(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_CONTACT=d0hanzibi+me@gmail.com\n", encoding="utf-8")
    settings = load_settings(
        env_file=env_file,
        environ={"MESHPROVISION_CONTACT": "you@example.com"},
        search_dotenv=False,
    )

    assert settings.contact_source == FROM_ENVIRONMENT
    assert settings.contact_hint().startswith(
        "MESHPROVISION_CONTACT is set in your environment, which overrides .env: unset it, "
        "or export your own email address or URL."
    )


def test_a_contact_override_forgets_where_the_old_one_came_from() -> None:
    settings = load_settings(
        environ={"MESHPROVISION_CONTACT": "you@example.com"},
        overrides={"contact": "d0hanzibi+me@gmail.com"},
        search_dotenv=False,
    )

    assert settings.contact_source is None


def test_a_client_that_sends_nothing_neither_needs_nor_checks_the_contact() -> None:
    for contact in (None, "you@example.com"):
        agent = Settings(contact=contact).user_agent(version="9.9.9", sends=False)
        assert agent == "meshprovision/9.9.9"


def test_user_agent_format() -> None:
    settings = Settings(contact="d0hanzibi+me@gmail.com")
    agent = settings.user_agent(version="9.9.9")
    assert agent == "meshprovision/9.9.9 (+d0hanzibi+me@gmail.com)"


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
    settings = Settings(contact="d0hanzibi+me@gmail.com")
    agent = settings.user_agent(version="9.9.9", require_contact=False)
    assert agent == "meshprovision/9.9.9 (+d0hanzibi+me@gmail.com)"


def test_with_overrides_returns_new_revalidated_instance() -> None:
    settings = Settings(contact="d0hanzibi+me@gmail.com")
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


def test_an_invalid_variable_from_the_environment_is_named_with_its_source() -> None:
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={"MESHPROVISION_CACHE_TTL": "abc"}, search_dotenv=False)

    text = str(exc_info.value)
    assert "MESHPROVISION_CACHE_TTL (from the environment): Input should be a valid number" in text
    assert "cache_ttl" not in text
    assert "abc" not in text
    assert exc_info.value.hint == (
        "Fix or unset it; every variable is described in "
        "docs/configuration.md#environment-variables."
    )


def test_an_invalid_variable_from_dotenv_names_the_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MESHPROVISION_LOG_LEVEL=foo\n", encoding="utf-8")

    with pytest.raises(SettingsError) as exc_info:
        load_settings(env_file=env_file, environ={}, search_dotenv=False)

    assert f"MESHPROVISION_LOG_LEVEL (from {env_file.absolute()}): Input should be" in str(
        exc_info.value
    )


def test_an_invalid_region_is_described_in_words() -> None:
    with pytest.raises(SettingsError) as exc_info:
        load_settings(environ={"MESHPROVISION_LORASTATS_REGIONS": "a/b"}, search_dotenv=False)

    text = str(exc_info.value)
    assert (
        "MESHPROVISION_LORASTATS_REGIONS (from the environment): Invalid lorastats region" in text
    )
    assert "1-64 characters without '/'" in text
    assert "Value error" not in text
    assert "\\x00" not in text


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
    assert "MESHPROVISION_LORASTATS_REGIONS (from the environment)" in exc_info.value.message


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
