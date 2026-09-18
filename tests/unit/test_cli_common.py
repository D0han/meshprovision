"""Tests for meshprovision.cli.common."""

from __future__ import annotations

import datetime as dt
import io
import logging
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Final

import click
import pytest
import structlog
from rich.console import Console

from meshprovision.cli.common import (
    CliContext,
    build_settings,
    configure_logging,
    echo_json,
    handle_cli_errors,
    resolve_non_interactive,
)
from meshprovision.config.settings import DEFAULT_CACHE_TTL, Settings
from meshprovision.errors import ExitCode, SchemaError

pytestmark = pytest.mark.unit

TRIPWIRE: Final[str] = "tripwire-local-value"
"""A value that only a ``show_locals=True`` traceback renderer could print."""


@pytest.fixture
def restore_logging() -> Iterator[None]:
    """Undo a test's ``configure_logging`` call, restoring pytest's own handlers.

    ``configure_logging`` strips every root handler by design, so a test
    that calls it would otherwise leave its own ``StringIO`` handler
    attached to the root logger for the rest of the session.

    Yields:
        ``None``, once, with the test body running in between.
    """
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    try:
        yield
    finally:
        for existing in list(root.handlers):
            root.removeHandler(existing)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)
        structlog.reset_defaults()


def _context(template_path: Path, buf: io.StringIO) -> CliContext:
    """Build a context whose stderr console writes into ``buf``.

    Args:
        template_path: The template the context should load.
        buf: The buffer the stderr console writes to.

    Returns:
        A :class:`CliContext` with capturable consoles.
    """
    return CliContext(
        settings=Settings(template_path=template_path),
        non_interactive=True,
        force_refresh=False,
        assume_yes=False,
        out=Console(file=io.StringIO()),
        err=Console(file=buf, no_color=True, width=200),
    )


def test_load_template_warns_through_the_styled_path(
    write_template: Callable[..., Path],
) -> None:
    """A template warning reaches stderr via ``warn``, not just structlog."""
    path = write_template(enabled_options=["not_a_real_module_option"])
    buf = io.StringIO()
    ctx = _context(path, buf)

    ctx.load_template()

    assert "warning: " in buf.getvalue()
    assert "not_a_real_module_option" in buf.getvalue()


def test_load_template_is_quiet_for_a_clean_template(
    write_template: Callable[..., Path],
) -> None:
    """An unmodified example template prints nothing to stderr."""
    buf = io.StringIO()
    ctx = _context(write_template(), buf)

    ctx.load_template()

    assert buf.getvalue() == ""


def test_click_abort_prints_aborted_and_exits_interrupted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``click.Abort`` is reported on stderr and mapped to INTERRUPTED."""

    @handle_cli_errors
    def _command() -> None:
        raise click.Abort

    with pytest.raises(SystemExit) as excinfo:
        _command()

    assert excinfo.value.code == int(ExitCode.INTERRUPTED)
    captured = capsys.readouterr()
    assert "Aborted." in captured.err
    assert captured.out == ""


def test_keyboard_interrupt_prints_interrupted_and_exits_interrupted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``KeyboardInterrupt`` is reported on stderr and mapped to INTERRUPTED.

    A silent exit here is indistinguishable from a hang or a crash --
    especially after a long, quiet BLE connect -- so this now matches
    ``click.Abort``'s behavior instead of exiting without a trace.
    """

    @handle_cli_errors
    def _command() -> None:
        raise KeyboardInterrupt

    with pytest.raises(SystemExit) as excinfo:
        _command()

    assert excinfo.value.code == int(ExitCode.INTERRUPTED)
    captured = capsys.readouterr()
    assert "Interrupted." in captured.err
    assert captured.out == ""


def _raise_with_secret_local() -> None:
    """Raise from a frame holding a local that ``show_locals=True`` would print.

    Raises:
        ValueError: Always. The message deliberately omits
            :data:`TRIPWIRE` itself, so the only way the value can reach
            a rendered traceback is via a locals-dumping formatter.
    """
    secret_value = TRIPWIRE
    raise ValueError(f"boom (length {len(secret_value)})")


@pytest.mark.usefixtures("restore_logging")
class TestConfigureLoggingTracebacks:
    def test_logged_traceback_never_dumps_frame_locals(self) -> None:
        """The plain exception formatter keeps frame locals out of logged tracebacks.

        ``ConsoleRenderer``'s own default is
        ``RichTracebackFormatter(show_locals=True)``, which would print
        every local -- including raw key material -- into the log.
        """
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False)

        try:
            _raise_with_secret_local()
        except ValueError:
            logging.getLogger("t").debug("command failed", exc_info=True)

        output = buf.getvalue()
        assert "Traceback (most recent call last)" in output
        assert "ValueError: boom" in output
        assert TRIPWIRE not in output
        assert "╭" not in output  # rich's boxed, locals-dumping traceback panel

    def test_configure_logging_rejects_an_unknown_level(self) -> None:
        with pytest.raises(SchemaError):
            configure_logging("LOUD", stream=io.StringIO())

    def test_configure_logging_is_idempotent(self) -> None:
        """Calling twice replaces the handler rather than stacking a second one."""
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False)
        configure_logging("DEBUG", stream=buf, colors=False)

        assert len(logging.getLogger().handlers) == 1

        logging.getLogger("t").warning("emitted-once")

        assert buf.getvalue().count("emitted-once") == 1

    def test_third_party_loggers_are_floored_by_name(self) -> None:
        """Noisy libraries are quieted individually, never via the root logger."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False)

        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("bleak").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("meshtastic").level == logging.WARNING
        assert logging.getLogger().level == logging.DEBUG

    def test_floored_loggers_stay_as_loud_as_requested(self) -> None:
        """``httpx``/``meshtastic`` follow a quieter root level; the rest stay at WARNING."""
        configure_logging("ERROR", stream=io.StringIO(), colors=False)

        assert logging.getLogger("httpx").level == logging.ERROR
        assert logging.getLogger("meshtastic").level == logging.ERROR
        assert logging.getLogger("httpcore").level == logging.WARNING


class TestBuildSettings:
    def test_each_cli_override_reaches_its_own_field(self, tmp_path: Path) -> None:
        """Every override kwarg lands on the matching ``Settings`` field."""
        settings = build_settings(
            db_path=tmp_path / "db.ods",
            template_path=tmp_path / "template.yaml",
            cache_ttl=12.5,
            log_level="debug",
        )

        assert settings.db_path == tmp_path / "db.ods"
        assert settings.template_path == tmp_path / "template.yaml"
        assert settings.cache_ttl == 12.5
        assert settings.log_level == "DEBUG"

    def test_no_overrides_leaves_every_default_intact(self) -> None:
        settings = build_settings()

        assert settings.cache_ttl == DEFAULT_CACHE_TTL
        assert settings.log_level == "WARNING"

    def test_a_none_override_never_clobbers_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Omitted CLI flags leave the ``MESHPROVISION_*`` values standing."""
        monkeypatch.setenv("MESHPROVISION_DB_PATH", str(tmp_path / "from-env.ods"))
        monkeypatch.setenv("MESHPROVISION_TEMPLATE_PATH", str(tmp_path / "from-env.yaml"))
        monkeypatch.setenv("MESHPROVISION_CACHE_TTL", "99.0")
        monkeypatch.setenv("MESHPROVISION_LOG_LEVEL", "ERROR")

        settings = build_settings()

        assert settings.db_path == tmp_path / "from-env.ods"
        assert settings.template_path == tmp_path / "from-env.yaml"
        assert settings.cache_ttl == 99.0
        assert settings.log_level == "ERROR"

    def test_an_override_beats_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MESHPROVISION_DB_PATH", str(tmp_path / "from-env.ods"))
        monkeypatch.setenv("MESHPROVISION_CACHE_TTL", "99.0")

        settings = build_settings(db_path=tmp_path / "from-flag.ods", cache_ttl=1.0)

        assert settings.db_path == tmp_path / "from-flag.ods"
        assert settings.cache_ttl == 1.0

    def test_env_file_is_read_and_still_loses_to_an_override(self, tmp_path: Path) -> None:
        env_file = tmp_path / "custom.env"
        env_file.write_text(
            f"MESHPROVISION_CACHE_TTL=77.0\nMESHPROVISION_DB_PATH={tmp_path / 'dotenv.ods'}\n",
            encoding="utf-8",
        )

        from_file = build_settings(env_file=env_file)
        overridden = build_settings(env_file=env_file, cache_ttl=3.0)

        assert from_file.cache_ttl == 77.0
        assert from_file.db_path == tmp_path / "dotenv.ods"
        assert overridden.cache_ttl == 3.0
        assert overridden.db_path == tmp_path / "dotenv.ods"


class TestEmitError:
    @pytest.mark.parametrize(
        "text",
        [
            "ref [ADMIN1] not found",
            "ref [red] not found",
            "ref [/] not found",
            "ref [link=x] not found",
        ],
    )
    def test_bracketed_operator_text_survives_verbatim(
        self, text: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Rich markup is off, so ``[...]`` in an error message is never interpreted."""

        @handle_cli_errors
        def _command() -> None:
            raise SchemaError(text)

        with pytest.raises(SystemExit):
            _command()

        assert text in capsys.readouterr().err


class TestEchoJson:
    def test_non_native_types_serialize_via_str(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A ``Path`` or ``datetime`` renders as its string form instead of raising."""
        moment = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC)

        echo_json({"path": Path("a/b.ods"), "when": moment})

        out = capsys.readouterr().out
        assert '"path": "a/b.ods"' in out
        assert f'"when": "{moment}"' in out


class _StdinStub:
    """A stand-in for ``sys.stdin`` whose ``isatty`` fails like a closed stream."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def isatty(self) -> bool:
        """Fail the way a closed or detached stream does.

        Raises:
            Exception: Always -- whichever error this stub was built with.
        """
        raise self._error


class TestResolveNonInteractive:
    @pytest.mark.parametrize("flag", [True, False])
    def test_an_explicit_flag_wins(self, flag: bool) -> None:
        assert resolve_non_interactive(flag) is flag

    @pytest.mark.parametrize("is_tty", [True, False])
    def test_autodetect_follows_stdin_tty(
        self, is_tty: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "stdin", io.StringIO())
        monkeypatch.setattr(sys.stdin, "isatty", lambda: is_tty, raising=False)

        assert resolve_non_interactive(None) is not is_tty

    @pytest.mark.parametrize(
        "error",
        [
            ValueError("I/O operation on closed file"),
            OSError("detached"),
            AttributeError("no isatty"),
        ],
    )
    def test_a_broken_stdin_falls_back_to_non_interactive(
        self, error: Exception, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A closed/detached stdin must never leave the CLI waiting on a prompt."""
        monkeypatch.setattr(sys, "stdin", _StdinStub(error))

        assert resolve_non_interactive(None) is True

    def test_a_missing_stdin_falls_back_to_non_interactive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "stdin", None)

        assert resolve_non_interactive(None) is True


class TestCliContextBuild:
    def test_defaults_env_file_to_none(self) -> None:
        ctx = CliContext.build(settings=Settings(), non_interactive=True, force_refresh=False)
        assert ctx.env_file is None

    def test_carries_the_given_env_file(self, tmp_path: Path) -> None:
        explicit = tmp_path / "custom.env"
        ctx = CliContext.build(
            settings=Settings(),
            non_interactive=True,
            force_refresh=False,
            env_file=explicit,
        )
        assert ctx.env_file == explicit


class TestCliContextWithSettings:
    """Covers the mechanism ``cli.main``'s callback uses.

    A contact the first-run wizard just prompted for must take effect
    for the rest of the same invocation, without a second ``.env`` parse.
    """

    def test_replaces_settings_without_mutating_the_original_context(self) -> None:
        original = CliContext.build(settings=Settings(), non_interactive=True, force_refresh=False)
        updated_settings = original.settings.with_overrides(contact="ops@example.org")

        updated = original.with_settings(updated_settings)

        assert updated.settings.contact == "ops@example.org"
        assert original.settings.contact is None

    def test_preserves_every_other_field(self, tmp_path: Path) -> None:
        original = CliContext.build(
            settings=Settings(),
            non_interactive=False,
            force_refresh=True,
            env_file=tmp_path / ".env",
        ).with_assume_yes(True)

        updated = original.with_settings(original.settings.with_overrides(contact="a@b.c"))

        assert updated.non_interactive == original.non_interactive
        assert updated.force_refresh == original.force_refresh
        assert updated.assume_yes == original.assume_yes
        assert updated.env_file == original.env_file
        assert updated.out is original.out
        assert updated.err is original.err
