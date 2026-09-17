"""``mesh init`` -- create whatever first-run artifacts are missing.

Two entry points into the same logic:

- :func:`init`, the explicit ``mesh init`` command -- scriptable via
  ``--yes``/``--contact``, safe to re-run (it only ever creates what is
  still missing).
- :func:`maybe_offer_setup`, called from ``cli.main``'s root group
  callback on every *other* interactive run: when setup is incomplete,
  it offers the same wizard before the requested command fails with
  today's "file not found" error.

Both funnel through :func:`run_setup`, the only place either prompts;
:mod:`meshprovision.cli.setup` stays prompt-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    MeshCommand,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
from meshprovision.cli.setup import (
    SetupItem,
    SetupStatus,
    create_env_file,
    create_template_file,
    inspect_setup,
    should_offer_setup,
    validate_contact,
)
from meshprovision.errors import SettingsError

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.cli.common import CliContext

__all__ = [
    "NEXT_STEPS",
    "SetupOutcome",
    "init",
    "maybe_offer_setup",
    "run_setup",
]

NEXT_STEPS: Final[tuple[str, ...]] = (
    "Edit config/template.yaml -- at minimum lora.region, the name patterns, and admin_nodes.",
    "mesh template validate",
    "mesh db verify",
    "mesh provision --dry-run --port /dev/ttyUSB0",
)
"""Printed after a successful setup, human-readable and in order."""

_CONTACT_PROMPT = "Contact address (email or URL) for lorastats.pl"
_CONTACT_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class SetupOutcome:
    """What :func:`run_setup` actually did.

    Attributes:
        created: Paths written this run, in creation order.
        present: Paths that were already there, so left untouched.
        declined: Paths the operator declined to create.
        notes: Any :class:`~meshprovision.cli.setup.SetupItem.note`
            values worth surfacing (currently only "``.env`` exists but
            contact is unset").
        contact: The contact string written into a freshly created
            ``.env`` this run, or ``None`` if the ``env`` artifact was
            already present or was declined. Lets a caller layer the
            answer onto its live :class:`~meshprovision.config.settings.
            Settings` via ``with_overrides`` instead of re-reading the
            ``.env`` it just wrote.
    """

    created: tuple[Path, ...]
    present: tuple[Path, ...]
    declined: tuple[Path, ...]
    notes: tuple[str, ...]
    contact: str | None = None

    @property
    def changed(self) -> bool:
        """Whether this run created at least one artifact.

        Returns:
            ``True`` if :attr:`created` is non-empty.
        """
        return bool(self.created)


def _prompt_for_contact(ctx: CliContext) -> str:
    """Prompt for a contact address, re-prompting on a blank/invalid answer.

    Args:
        ctx: The shared CLI context.

    Returns:
        A validated contact string.

    Raises:
        NonInteractiveError: If the run is non-interactive --
            :meth:`CliContext.prompt` raises on the first attempt, so
            this never actually loops in that case.
        SettingsError: If the last of :data:`_CONTACT_ATTEMPTS` answers
            is still blank/invalid.
    """
    for attempt in range(_CONTACT_ATTEMPTS):
        raw = ctx.prompt(_CONTACT_PROMPT)
        try:
            return validate_contact(raw)
        except SettingsError as exc:
            if attempt == _CONTACT_ATTEMPTS - 1:
                raise
            ctx.warn(str(exc))
    raise AssertionError("unreachable")  # pragma: no cover


def _create_item(ctx: CliContext, item: SetupItem, *, contact: str | None) -> str | None:
    """Prompt for and create a single missing artifact.

    Args:
        ctx: The shared CLI context (for ``confirm``/``prompt``).
        item: The missing artifact to create.
        contact: A pre-supplied contact (``--contact``/an earlier
            prompt in this same run), or ``None`` to prompt for one
            when ``item.kind == "env"``.

    Returns:
        The contact string used, if ``item.kind == "env"``; otherwise
        ``None``.
    """
    if item.kind == "env":
        # An explicitly supplied --contact is validated directly, with no
        # re-prompt loop, since it isn't a shape the operator can retype.
        answer = validate_contact(contact) if contact is not None else _prompt_for_contact(ctx)
        create_env_file(item.path, contact=answer)
        return answer
    if item.kind == "template":
        create_template_file(item.path)
        return None
    # "database": creating an empty, schema-correct database is already
    # exactly what CliContext.open_database(must_exist=False) does --
    # reusing it here means this module never imports the db layer.
    with ctx.open_database(must_exist=False):
        pass
    return None


def run_setup(
    ctx: CliContext, status: SetupStatus, *, contact: str | None = None, banner: bool = False
) -> SetupOutcome:
    """Create every missing first-run artifact, prompting as needed.

    The only prompting code in either this module or
    :mod:`meshprovision.cli.setup`. Honours :attr:`CliContext.
    assume_yes` (skips every confirmation) and raises
    :class:`~meshprovision.errors.NonInteractiveError` through
    :meth:`CliContext.confirm`/:meth:`CliContext.prompt` when the run is
    non-interactive and an answer is actually needed.

    Args:
        ctx: The shared CLI context.
        status: The current :class:`~meshprovision.cli.setup.SetupStatus`.
        contact: A pre-supplied contact, from ``--contact``. Skips the
            prompt for the ``env`` artifact when given.
        banner: Whether to print an introductory banner and ask one
            top-level confirmation before creating anything -- used by
            the auto-offer path, not by ``mesh init`` itself (which is
            already an explicit request).

    Returns:
        A :class:`SetupOutcome` describing what happened.
    """
    missing = status.missing
    notes = tuple(item.note for item in status.items if item.note)

    if not missing:
        return SetupOutcome(
            created=(), present=tuple(item.path for item in status.items), declined=(), notes=notes
        )

    if banner:
        cwd_hint = missing[0].path.parent
        ctx.info(f"No meshprovision setup found in {cwd_hint}.")
        for item in missing:
            ctx.info(f"  {item.path}  (missing)")
        if not ctx.confirm(f"Create the missing file(s) above in {cwd_hint}?", default=True):
            ctx.info("Skipped. Run `mesh init` any time to create them.")
            return SetupOutcome(
                created=(),
                present=tuple(item.path for item in status.items if item.present),
                declined=tuple(item.path for item in missing),
                notes=notes,
            )

    created: list[Path] = []
    declined: list[Path] = []
    used_contact = contact
    env_created = False
    for item in missing:
        if not banner and not ctx.confirm(f"Create {item.path}?", default=True):
            declined.append(item.path)
            continue
        answer = _create_item(ctx, item, contact=used_contact)
        if item.kind == "env" and answer is not None:
            used_contact = answer
            env_created = True
        created.append(item.path)
        ctx.success(f"Created {item.path}")

    if created:
        ctx.info("Next steps:")
        for index, step in enumerate(NEXT_STEPS, start=1):
            ctx.info(f"  {index}. {step}")

    present = tuple(item.path for item in status.items if item.present)
    return SetupOutcome(
        created=tuple(created),
        present=present,
        declined=tuple(declined),
        notes=notes,
        contact=used_contact if env_created else None,
    )


def maybe_offer_setup(ctx: CliContext, *, click_ctx: click.Context) -> SetupOutcome | None:
    """Offer first-run setup on an interactive run, if anything is missing.

    Called once from the root ``mesh`` group callback, after settings
    and the provisional :class:`CliContext` are built.

    Args:
        ctx: The (provisional) shared CLI context -- ``ctx.env_file`` is
            the explicit ``--env-file`` value, or ``None``.
        click_ctx: The root click context -- read for
            ``invoked_subcommand`` and whether help was requested
            anywhere in this invocation.

    Returns:
        ``None`` if setup was not offered (non-interactive, help-only,
        ``mesh init`` itself, or already complete); otherwise the
        :class:`SetupOutcome`.
    """
    from meshprovision.cli.common import help_requested

    status = inspect_setup(ctx.settings, env_file=ctx.env_file)
    if not should_offer_setup(
        status=status,
        non_interactive=ctx.non_interactive,
        help_requested=help_requested(click_ctx),
        invoked_subcommand=click_ctx.invoked_subcommand,
    ):
        return None
    return run_setup(ctx, status, banner=True)


@click.command(name="init", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@click.option(
    "-y", "--yes", is_flag=True, default=False, help="Create every missing file without asking."
)
@click.option("--contact", default=None, help="Value for MESHPROVISION_CONTACT; skips the prompt.")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def init(ctx: CliContext, *, yes: bool, contact: str | None, json_output: bool) -> None:
    """Create the first-run workspace: ``.env``, the template, and the node database.

    Only creates what is missing -- safe to re-run. Honours every
    ``--db-path``/``--template-path``/``--env-file``/``MESHPROVISION_*``
    override already in effect for this invocation.
    """
    ctx = ctx.with_assume_yes(yes)
    status = inspect_setup(ctx.settings, env_file=ctx.env_file)

    if status.complete:
        ctx.info("Setup is already complete:")
        for item in status.items:
            ctx.info(f"  {item.path}")
        if json_output:
            echo_json({"created": [], "present": [str(i.path) for i in status.items]})
        return

    outcome = run_setup(ctx, status, contact=contact)
    if json_output:
        echo_json(
            {
                "created": [str(p) for p in outcome.created],
                "present": [str(p) for p in outcome.present],
                "declined": [str(p) for p in outcome.declined],
                "notes": list(outcome.notes),
            }
        )
