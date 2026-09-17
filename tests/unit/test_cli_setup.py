"""Tests for meshprovision.cli.setup -- first-run artifact inspection and writers."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from meshprovision.cli.setup import (
    ENV_EXAMPLE_NAME,
    TEMPLATE_EXAMPLE_NAME,
    SetupItem,
    SetupStatus,
    create_env_file,
    create_template_file,
    example_path,
    inspect_setup,
    read_example_text,
    render_env_text,
    should_offer_setup,
    validate_contact,
    write_new_file,
)
from meshprovision.config.settings import Settings
from meshprovision.errors import ConfigError, SettingsError

pytestmark = pytest.mark.unit


class TestExamplePath:
    def test_resolves_inside_the_package_examples_directory(self) -> None:
        path = example_path(ENV_EXAMPLE_NAME)
        assert path.name == ENV_EXAMPLE_NAME
        assert path.parent.name == "examples"

    def test_env_example_exists_on_disk(self) -> None:
        assert example_path(ENV_EXAMPLE_NAME).is_file()

    def test_template_example_exists_on_disk(self) -> None:
        assert example_path(TEMPLATE_EXAMPLE_NAME).is_file()


class TestReadExampleText:
    def test_reads_the_bundled_env_example(self) -> None:
        text = read_example_text(ENV_EXAMPLE_NAME)
        assert "MESHPROVISION_CONTACT" in text

    def test_raises_config_error_with_a_reinstall_hint_when_missing(self) -> None:
        with pytest.raises(ConfigError) as exc_info:
            read_example_text("does-not-exist.example")
        assert "Reinstall" in (exc_info.value.hint or "")


class TestInspectSetup:
    def test_reports_everything_missing_in_an_empty_directory(self, tmp_path: Path) -> None:
        settings = Settings(
            db_path=tmp_path / "data" / "nodes_db.ods",
            template_path=tmp_path / "config" / "template.yaml",
        )
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert not status.complete
        assert {item.kind for item in status.missing} == {"env", "template", "database"}

    def test_resolves_paths_from_settings_overrides(self, tmp_path: Path) -> None:
        db_path = tmp_path / "custom" / "db.ods"
        template_path = tmp_path / "custom" / "tpl.yaml"
        settings = Settings(db_path=db_path, template_path=template_path)
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert status.database.path == db_path
        assert status.template.path == template_path

    def test_template_and_database_present_when_files_exist(self, tmp_path: Path) -> None:
        db_path = tmp_path / "nodes_db.ods"
        template_path = tmp_path / "template.yaml"
        db_path.write_text("x", encoding="utf-8")
        template_path.write_text("x", encoding="utf-8")
        settings = Settings(db_path=db_path, template_path=template_path)
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert status.template.present
        assert status.database.present

    def test_env_present_when_settings_contact_is_already_set(self, tmp_path: Path) -> None:
        settings = Settings(
            db_path=tmp_path / "db.ods", template_path=tmp_path / "tpl.yaml", contact="a@b.c"
        )
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert status.env.present
        assert status.env.note is None

    def test_env_present_with_a_note_when_env_file_exists_but_contact_is_unset(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".env").write_text("MESHPROVISION_CONTACT=\n", encoding="utf-8")
        settings = Settings(db_path=tmp_path / "db.ods", template_path=tmp_path / "tpl.yaml")
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert status.env.present
        assert status.env.note is not None
        assert "MESHPROVISION_CONTACT" in status.env.note

    def test_env_missing_when_no_env_file_and_no_contact(self, tmp_path: Path) -> None:
        settings = Settings(db_path=tmp_path / "db.ods", template_path=tmp_path / "tpl.yaml")
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert not status.env.present
        assert status.env.path == tmp_path / ".env"

    def test_env_found_above_the_cwd_via_upward_search(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("MESHPROVISION_CONTACT=a@b.c\n", encoding="utf-8")
        nested = tmp_path / "nested" / "deeper"
        nested.mkdir(parents=True)
        settings = Settings(db_path=nested / "db.ods", template_path=nested / "tpl.yaml")
        status = inspect_setup(settings, env_file=None, cwd=nested)
        assert status.env.path == tmp_path / ".env"

    def test_explicit_env_file_overrides_the_upward_search(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("MESHPROVISION_CONTACT=a@b.c\n", encoding="utf-8")
        explicit = tmp_path / "custom.env"
        settings = Settings(db_path=tmp_path / "db.ods", template_path=tmp_path / "tpl.yaml")
        status = inspect_setup(settings, env_file=explicit, cwd=tmp_path)
        assert status.env.path == explicit
        assert not status.env.present

    def test_missing_returns_env_template_database_order(self, tmp_path: Path) -> None:
        settings = Settings(db_path=tmp_path / "db.ods", template_path=tmp_path / "tpl.yaml")
        status = inspect_setup(settings, env_file=None, cwd=tmp_path)
        assert [item.kind for item in status.missing] == ["env", "template", "database"]


class TestShouldOfferSetup:
    def _status(self, *, complete: bool) -> SetupStatus:
        env = SetupItem(kind="env", path=Path("x"), present=complete)
        template = SetupItem(kind="template", path=Path("y"), present=complete)
        database = SetupItem(kind="database", path=Path("z"), present=complete)
        return SetupStatus(env=env, template=template, database=database)

    def test_false_when_non_interactive(self) -> None:
        assert not should_offer_setup(
            status=self._status(complete=False),
            non_interactive=True,
            help_requested=False,
            invoked_subcommand="status",
        )

    def test_false_when_help_requested(self) -> None:
        assert not should_offer_setup(
            status=self._status(complete=False),
            non_interactive=False,
            help_requested=True,
            invoked_subcommand="status",
        )

    def test_false_for_the_init_subcommand(self) -> None:
        assert not should_offer_setup(
            status=self._status(complete=False),
            non_interactive=False,
            help_requested=False,
            invoked_subcommand="init",
        )

    def test_false_when_setup_is_already_complete(self) -> None:
        assert not should_offer_setup(
            status=self._status(complete=True),
            non_interactive=False,
            help_requested=False,
            invoked_subcommand="status",
        )

    def test_true_on_a_bare_interactive_first_run(self) -> None:
        assert should_offer_setup(
            status=self._status(complete=False),
            non_interactive=False,
            help_requested=False,
            invoked_subcommand="status",
        )


class TestValidateContact:
    @pytest.mark.parametrize("raw", ["", "   ", "a\nb", "a\rb", "\t"])
    def test_rejects_blank_and_line_break_values(self, raw: str) -> None:
        with pytest.raises(SettingsError):
            validate_contact(raw)

    def test_strips_surrounding_whitespace(self) -> None:
        assert validate_contact("  ops@example.org  ") == "ops@example.org"


class TestRenderEnvText:
    def test_replaces_the_contact_assignment_and_keeps_every_comment(self) -> None:
        example = "# a comment\nMESHPROVISION_CONTACT=\n# another comment\n"
        rendered = render_env_text(example, contact="ops@example.org")
        assert "# a comment" in rendered
        assert "# another comment" in rendered
        assert "MESHPROVISION_CONTACT=ops@example.org" in rendered

    def test_uses_the_real_bundled_example(self) -> None:
        rendered = render_env_text(read_example_text(ENV_EXAMPLE_NAME), contact="ops@example.org")
        assert "MESHPROVISION_CONTACT=ops@example.org" in rendered
        assert rendered.count("MESHPROVISION_CONTACT=") == 1

    def test_appends_a_contact_line_when_the_example_has_none(self) -> None:
        rendered = render_env_text("# nothing here\n", contact="ops@example.org")
        assert "MESHPROVISION_CONTACT=ops@example.org" in rendered

    def test_quotes_a_value_containing_whitespace(self) -> None:
        rendered = render_env_text("MESHPROVISION_CONTACT=\n", contact="Ops Team <a@b.c>")
        assert 'MESHPROVISION_CONTACT="Ops Team <a@b.c>"' in rendered

    def test_quotes_a_value_containing_a_hash(self) -> None:
        rendered = render_env_text("MESHPROVISION_CONTACT=\n", contact="a@b.c #note")
        assert 'MESHPROVISION_CONTACT="a@b.c #note"' in rendered


class TestWriteNewFile:
    def test_creates_the_file_with_the_given_text(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        write_new_file(target, "hello")
        assert target.read_text(encoding="utf-8") == "hello"

    def test_creates_missing_parent_directories(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c.txt"
        write_new_file(target, "hello")
        assert target.read_text(encoding="utf-8") == "hello"

    def test_refuses_to_overwrite_an_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        target.write_text("original", encoding="utf-8")
        with pytest.raises(ConfigError):
            write_new_file(target, "clobbered")
        assert target.read_text(encoding="utf-8") == "original"

    def test_applies_the_requested_mode(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.env"
        write_new_file(target, "x", mode=0o600)
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_wraps_a_permission_error_opening_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise(*_args: object, **_kwargs: object) -> int:
            raise PermissionError("denied")

        monkeypatch.setattr(os, "open", _raise)
        with pytest.raises(ConfigError, match="Could not create"):
            write_new_file(tmp_path / "out.txt", "hello")

    def test_wraps_an_os_error_while_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _BoomFile:
            def write(self, _text: str) -> int:
                raise OSError("disk full")

            def __enter__(self) -> _BoomFile:
                return self

            def __exit__(self, *_exc_info: object) -> None:
                return None

        monkeypatch.setattr(os, "fdopen", lambda *_a, **_k: _BoomFile())
        with pytest.raises(ConfigError, match="Could not write"):
            write_new_file(tmp_path / "out.txt", "hello")


class TestCreateEnvFile:
    def test_writes_a_rendered_env_file_that_is_owner_readable_only(self, tmp_path: Path) -> None:
        target = tmp_path / ".env"
        create_env_file(target, contact="ops@example.org")
        assert "MESHPROVISION_CONTACT=ops@example.org" in target.read_text(encoding="utf-8")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_refuses_to_overwrite_an_existing_env_file(self, tmp_path: Path) -> None:
        target = tmp_path / ".env"
        target.write_text("MESHPROVISION_CONTACT=already-here\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            create_env_file(target, contact="new@example.org")
        assert "already-here" in target.read_text(encoding="utf-8")


class TestCreateTemplateFile:
    def test_writes_the_bundled_example_verbatim(self, tmp_path: Path) -> None:
        target = tmp_path / "template.yaml"
        create_template_file(target)
        assert target.read_text(encoding="utf-8") == read_example_text(TEMPLATE_EXAMPLE_NAME)

    def test_refuses_to_overwrite_an_existing_template(self, tmp_path: Path) -> None:
        target = tmp_path / "template.yaml"
        target.write_text("version: 1\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            create_template_file(target)
