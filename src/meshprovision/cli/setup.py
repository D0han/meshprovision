"""What a first ``mesh`` run needs on disk, and how to create it.

Pure, prompt-free logic: nothing here reads a click context, prints, or
prompts -- the interactive shell in :mod:`meshprovision.cli.init_cmd`
supplies every answer and does the printing, matching how this project
already keeps prompts out of its core layers (see
:mod:`meshprovision.provisioning.pipeline`'s own docstring).

The three first-run artifacts, and how each is created:

- ``.env`` -- rendered from the bundled ``env.example`` with
  ``MESHPROVISION_CONTACT`` filled in.
- The provisioning template -- copied from the bundled
  ``template.example.yaml`` verbatim; the template stays the one place
  ``mesh`` policy is authored, so nothing here edits its contents.
- The node database -- deliberately **not** copied from
  ``data/nodes_db.example.ods``, which ships 3 fake node rows and 4 fake
  key rows for illustration. Creating it is left to
  :meth:`~meshprovision.cli.common.CliContext.open_database`
  (``must_exist=False``), which already builds a schema-correct empty
  database via :func:`meshprovision.db.ods.create_empty` -- so this
  module does not need to import the database layer at all.

Every write here refuses to overwrite an existing file: :func:`write_new_file`
uses ``os.O_EXCL`` so the guarantee comes from the kernel, not a
check-then-write race.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

from meshprovision.config.settings import find_env_file
from meshprovision.errors import ConfigError, SettingsError

if TYPE_CHECKING:
    from meshprovision.config.settings import Settings

__all__ = [
    "ENV_EXAMPLE_NAME",
    "TEMPLATE_EXAMPLE_NAME",
    "SetupItem",
    "SetupStatus",
    "create_env_file",
    "create_template_file",
    "example_path",
    "inspect_setup",
    "read_example_text",
    "render_env_text",
    "should_offer_setup",
    "validate_contact",
    "write_new_file",
]

ENV_EXAMPLE_NAME: Final[str] = "env.example"
"""Filename of the bundled ``.env`` template under the package's ``examples/`` dir."""

TEMPLATE_EXAMPLE_NAME: Final[str] = "template.example.yaml"
"""Filename of the bundled provisioning template under ``examples/``."""

_EXAMPLES_DIR: Final[Path] = Path(__file__).resolve().parent.parent / "examples"
"""``src/meshprovision/examples/`` -- ships inside every install (wheel,
sdist, or editable checkout) because it lives inside the package itself,
unlike ``data/nodes_db.example.ods`` or ``data/known_bad_keys.txt``,
which stay outside ``src/`` and need their own resolution (see
:func:`meshprovision.crypto.weakkeys.default_known_bad_keys_path`)."""

_CONTACT_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^MESHPROVISION_CONTACT[ \t]*=.*$", re.MULTILINE
)
"""Matches the single uncommented ``MESHPROVISION_CONTACT=`` line in ``env.example``."""


def example_path(name: str) -> Path:
    """Resolve a bundled example file's on-disk path.

    Args:
        name: The example's filename under the package's ``examples/``
            directory, e.g. :data:`ENV_EXAMPLE_NAME`.

    Returns:
        The absolute path to the bundled copy.
    """
    return _EXAMPLES_DIR / name


def read_example_text(name: str) -> str:
    """Read a bundled example file's text.

    Args:
        name: The example's filename, e.g. :data:`ENV_EXAMPLE_NAME`.

    Returns:
        The file's UTF-8 text.

    Raises:
        ConfigError: If the bundled example is missing. Should not
            happen in a normal install -- the hint points at
            reinstalling.
    """
    path = example_path(name)
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(
            f"Bundled example not found: {path}",
            hint="Reinstall meshprovision, or create the file by hand.",
        ) from exc


@dataclass(frozen=True, slots=True)
class SetupItem:
    """One first-run artifact: what it is, where it goes, and its state.

    Attributes:
        kind: Which artifact this is.
        path: The absolute target path, resolved from the current
            :class:`~meshprovision.config.settings.Settings` (and, for
            ``env``, ``--env-file``/the upward ``.env`` search) -- so it
            already honours every ``--db-path``/``--template-path``/
            ``--env-file``/``MESHPROVISION_*`` override in effect.
        present: Whether this artifact already satisfies setup. For
            ``env`` this is ``True`` once a contact is configured *at
            all* (env var, `.env` above the CWD, or an existing local
            ``.env``) -- not only when a local ``.env`` file exists --
            so the wizard never nags an operator who already set
            ``MESHPROVISION_CONTACT`` some other way.
        note: An optional human-readable detail, shown as a hint rather
            than acted on. Used for the one case that isn't simply
            present/absent: an existing ``.env`` whose contact is blank.
    """

    kind: Literal["env", "template", "database"]
    path: Path
    present: bool
    note: str | None = None


@dataclass(frozen=True, slots=True)
class SetupStatus:
    """The full first-run picture: one :class:`SetupItem` per artifact.

    Attributes:
        env: The ``.env`` artifact.
        template: The provisioning template artifact.
        database: The node database artifact.
    """

    env: SetupItem
    template: SetupItem
    database: SetupItem

    @property
    def items(self) -> tuple[SetupItem, ...]:
        """Every artifact, in the fixed ``env, template, database`` order.

        Returns:
            A 3-tuple: ``(self.env, self.template, self.database)``.
        """
        return (self.env, self.template, self.database)

    @property
    def missing(self) -> tuple[SetupItem, ...]:
        """Every artifact that is not yet present, in creation order.

        Returns:
            The subset of :attr:`items` whose ``present`` is ``False``.
        """
        return tuple(item for item in self.items if not item.present)

    @property
    def complete(self) -> bool:
        """Whether every artifact is already present.

        Returns:
            ``True`` if :attr:`missing` is empty.
        """
        return not self.missing


def inspect_setup(
    settings: Settings, *, env_file: Path | None, cwd: Path | None = None
) -> SetupStatus:
    """Report which first-run artifacts are missing, without touching disk.

    Args:
        settings: The layered, already-built settings -- ``template_path``
            and ``db_path`` already reflect every override in effect.
        env_file: The explicit ``--env-file`` value, or ``None`` to
            search upward from ``cwd`` the same way
            :func:`~meshprovision.config.settings.load_settings` does.
        cwd: The directory to resolve relative paths and the ``.env``
            search against. Defaults to :meth:`Path.cwd`.

    Returns:
        A :class:`SetupStatus` describing all three artifacts.
    """
    base = cwd if cwd is not None else Path.cwd()

    if env_file is not None:
        env_path = Path(env_file).expanduser()
    else:
        found = find_env_file(base)
        env_path = found if found is not None else base / ".env"

    if settings.contact is not None:
        env_item = SetupItem(kind="env", path=env_path, present=True)
    elif env_path.is_file():
        env_item = SetupItem(
            kind="env",
            path=env_path,
            present=True,
            note=f"{env_path} exists but MESHPROVISION_CONTACT is unset or blank.",
        )
    else:
        env_item = SetupItem(kind="env", path=env_path, present=False)

    template_item = SetupItem(
        kind="template", path=settings.template_path, present=settings.template_path.is_file()
    )
    database_item = SetupItem(
        kind="database", path=settings.db_path, present=settings.db_path.is_file()
    )
    return SetupStatus(env=env_item, template=template_item, database=database_item)


def should_offer_setup(
    *,
    status: SetupStatus,
    non_interactive: bool,
    help_requested: bool,
    invoked_subcommand: str | None,
) -> bool:
    """Decide whether ``mesh`` should offer to run first-run setup.

    Args:
        status: The current :class:`SetupStatus`.
        non_interactive: The resolved ``--non-interactive`` setting --
            piped, CI, and closed-stdin runs never see the offer, and
            keep today's exact error-and-hint behavior instead.
        help_requested: Whether a ``-h``/``--help`` flag appeared
            anywhere in this invocation (see
            :func:`meshprovision.cli.common.help_requested`).
        invoked_subcommand: ``click.Context.invoked_subcommand`` -- the
            name of the subcommand about to run, or ``None``.

    Returns:
        ``False`` when non-interactive, help-only, running ``mesh init``
        itself (which does its own inspection), or setup is already
        complete; ``True`` otherwise.
    """
    if non_interactive or help_requested:
        return False
    if invoked_subcommand == "init":
        return False
    return not status.complete


def validate_contact(raw: str) -> str:
    """Validate an operator-supplied contact string.

    Mirrors :meth:`~meshprovision.config.settings.Settings.
    _blank_contact_is_unset`'s notion of "blank", plus a guard against
    a stray newline corrupting the ``.env`` file it will be written
    into.

    Args:
        raw: The raw answer to validate.

    Returns:
        ``raw``, stripped of leading/trailing whitespace.

    Raises:
        SettingsError: If ``raw`` is blank/whitespace-only, or contains
            a carriage return or newline.
    """
    stripped = raw.strip()
    if not stripped:
        raise SettingsError(
            "Contact address cannot be blank.",
            hint="Enter your own email address or URL.",
        )
    if "\n" in stripped or "\r" in stripped:
        raise SettingsError(
            "Contact address cannot contain a line break.",
            hint="Enter a single-line email address or URL.",
        )
    return stripped


def render_env_text(example_text: str, *, contact: str) -> str:
    """Return ``env.example``'s text with ``MESHPROVISION_CONTACT`` filled in.

    Every other line -- comments, every other variable, blank lines --
    is left byte-for-byte as shipped.

    Args:
        example_text: The bundled example's raw text.
        contact: The validated contact string to fill in. Quoted with
            double quotes when it contains whitespace or ``#`` --
            ``python-dotenv`` would otherwise treat a ` #` as starting
            an inline comment, or split on internal whitespace.

    Returns:
        The rendered ``.env`` text.
    """
    value = f'"{contact}"' if (" " in contact or "#" in contact) else contact
    replacement = f"MESHPROVISION_CONTACT={value}"
    text, count = _CONTACT_LINE_RE.subn(replacement, example_text, count=1)
    if count == 0:
        text = text.rstrip("\n") + f"\n{replacement}\n"
    return text


def write_new_file(path: Path, text: str, *, mode: int = 0o644) -> None:
    """Write ``text`` to ``path``, refusing to overwrite an existing file.

    Uses ``os.O_EXCL`` so the no-clobber guarantee comes from the
    kernel rather than a separate ``.exists()`` check racing the write.
    Creates any missing parent directories first.

    Args:
        path: The file to create.
        text: The UTF-8 text to write.
        mode: The file's permission bits, passed to ``os.open``.

    Raises:
        ConfigError: If ``path`` already exists, or the write fails for
            any other OS-level reason.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    except FileExistsError as exc:
        raise ConfigError(f"Refusing to overwrite an existing file: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"Could not create {path}: {exc}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        raise ConfigError(f"Could not write {path}: {exc}") from exc


def create_env_file(path: Path, *, contact: str) -> None:
    """Create ``.env``, rendered from the bundled example, owner-readable only.

    Args:
        path: Where to write the file.
        contact: The validated contact string; see :func:`render_env_text`.

    Raises:
        ConfigError: If ``path`` already exists or the write fails.
    """
    text = render_env_text(read_example_text(ENV_EXAMPLE_NAME), contact=contact)
    write_new_file(path, text, mode=0o600)


def create_template_file(path: Path) -> None:
    """Copy the bundled example template to ``path``, verbatim.

    Args:
        path: Where to write the file.

    Raises:
        ConfigError: If ``path`` already exists or the write fails.
    """
    write_new_file(path, read_example_text(TEMPLATE_EXAMPLE_NAME))
