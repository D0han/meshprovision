"""``mesh template`` group -- ``validate``.

``mesh db verify`` already runs a template cross-check as part of
validating a database, but that requires an existing, loadable ``.ods``
file and deliberately *degrades* a template failure to a warning (see its
own docstring) -- verifying a database has to keep working even with a
broken template. There was previously no fast, device-free,
database-free way to just check "is my template valid" on its own.
``mesh template validate`` is exactly that: it calls
:func:`~meshprovision.config.template.load_template` directly (via
:meth:`~meshprovision.cli.common.CliContext.load_template`, the same
loader every other command uses) and lets a template failure be the
command's own real, non-degraded result.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    MeshGroup,
    echo_json,
    handle_cli_errors,
    pass_cli,
)

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext

__all__ = [
    "template",
    "template_validate",
]


@click.group(name="template", cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
def template() -> None:
    """Provisioning template file operations."""


@template.command(name="validate")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def template_validate(ctx: CliContext, *, json_output: bool) -> None:
    """Validate the configured provisioning template, with no database or device needed.

    Uses whichever template path ``--template-path``/
    ``MESHPROVISION_TEMPLATE_PATH``/``.env`` resolves to, exactly like
    every other command -- there is no separate override here.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        TemplateValidationError: If the template file is missing, not
            UTF-8, not valid YAML, or fails :class:`~meshprovision.config.
            template.TemplateConfig` validation.
        NamePatternError: If a name pattern overflows its firmware byte
            limit.
        NameCapacityError: If a name pattern's namespace capacity is
            below the configured floor.
        AdminKeyCapacityError: If more than three admin nodes are
            configured.
    """
    tmpl = ctx.load_template()

    ctx.success(f"Template OK: {ctx.settings.template_path}")
    if json_output:
        echo_json(
            {
                "template_path": str(ctx.settings.template_path),
                "admin_nodes": list(tmpl.admin_nodes),
                "short_name_pattern": tmpl.short_name_pattern,
                "long_name_pattern": tmpl.long_name_pattern,
                "warnings": [
                    {"code": w.code, "message": w.message, "field": w.field}
                    for w in tmpl.collect_warnings()
                ],
            }
        )
