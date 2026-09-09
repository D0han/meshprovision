"""Application settings, loaded from environment variables and ``.env``.

:class:`Settings` is a frozen ``pydantic`` model covering everything the
``mesh`` console script needs before it can do anything else: where the
ODS database and provisioning template live, where the HTTP response
cache is stored, how long cached entries stay fresh, the operator's
contact string (required by lorastats.pl), and the logging verbosity.

:func:`load_settings` builds a :class:`Settings` instance by layering,
from lowest to highest precedence: an optional ``.env`` file, the process
environment, and explicit programmatic overrides. ``os.environ`` itself
is never mutated -- every layer is read into a plain ``dict`` first, so
loading settings twice in the same process (as tests routinely do) never
leaks state between calls.

This module is a leaf within the ``config`` group: :mod:`meshprovision.
config.template` imports :func:`format_validation_error` from here, but
this module imports nothing from ``meshprovision.config.template``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, TypeAlias

import dotenv
import platformdirs
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from meshprovision.errors import MissingContactError, SettingsError

_logger = logging.getLogger(__name__)

__all__ = [
    "APP_NAME",
    "DEFAULT_CACHE_TTL",
    "DEFAULT_DB_PATH",
    "DEFAULT_LOG_LEVEL",
    "DEFAULT_TEMPLATE_PATH",
    "ENV_FIELD_MAP",
    "ENV_PREFIX",
    "LogLevel",
    "Settings",
    "default_cache_dir",
    "find_env_file",
    "format_validation_error",
    "load_settings",
]

APP_NAME: Final[str] = "meshprovision"
"""Application name used for the platform cache directory and elsewhere."""

ENV_PREFIX: Final[str] = "MESHPROVISION_"
"""Prefix shared by every environment variable meshprovision reads."""

DEFAULT_DB_PATH: Final[Path] = Path("data/nodes_db.ods")
"""Default path to the ODS node database, relative to the CWD."""

DEFAULT_TEMPLATE_PATH: Final[Path] = Path("config/template.yaml")
"""Default path to the provisioning template, relative to the CWD."""

DEFAULT_CACHE_TTL: Final[float] = 300.0
"""Default HTTP response cache time-to-live, in seconds."""

DEFAULT_LOG_LEVEL: Final[str] = "INFO"
"""Default logging verbosity."""

LogLevel: TypeAlias = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
"""The set of logging verbosities accepted by :attr:`Settings.log_level`."""

ENV_FIELD_MAP: Final[Mapping[str, str]] = MappingProxyType(
    {
        "MESHPROVISION_DB_PATH": "db_path",
        "MESHPROVISION_TEMPLATE_PATH": "template_path",
        "MESHPROVISION_CACHE_DIR": "cache_dir",
        "MESHPROVISION_CACHE_TTL": "cache_ttl",
        "MESHPROVISION_CONTACT": "contact",
        "MESHPROVISION_LOG_LEVEL": "log_level",
    }
)
"""Maps every supported ``MESHPROVISION_*`` environment variable to the
:class:`Settings` field it populates."""


def default_cache_dir() -> Path:
    """Return the platform-appropriate user cache directory.

    Uses ``platformdirs`` so the location follows OS convention (for
    example ``~/.cache/meshprovision`` on Linux) without meshprovision
    having to special-case any platform itself.

    Returns:
        The default cache directory for meshprovision.
    """
    return Path(platformdirs.user_cache_dir(APP_NAME, appauthor=False))


class Settings(BaseModel):
    """Top-level application settings.

    Immutable once constructed (``frozen=True``): callers that need a
    modified copy use :meth:`with_overrides` rather than mutating fields
    in place, matching the project's immutability convention.

    Attributes:
        db_path: Path to the ODS node database.
        template_path: Path to the provisioning template YAML file.
        cache_dir: Directory the HTTP response cache is stored under.
        cache_ttl: HTTP response cache time-to-live, in seconds.
        contact: Operator contact string sent to lorastats.pl in the
            ``User-Agent`` header. ``None`` when unset -- there is
            deliberately no default value.
        log_level: Logging verbosity for the ``mesh`` console script.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )

    db_path: Path = DEFAULT_DB_PATH
    template_path: Path = DEFAULT_TEMPLATE_PATH
    cache_dir: Path = Field(default_factory=default_cache_dir)
    cache_ttl: float = Field(default=DEFAULT_CACHE_TTL, ge=0.0)
    contact: str | None = None
    log_level: LogLevel = "INFO"

    @field_validator("db_path", "template_path", "cache_dir", mode="after")
    @classmethod
    def _expand(cls, value: Path) -> Path:
        """Expand a leading ``~`` in a path field.

        Relative paths are left relative to the current working
        directory (documented in ``.env.example``); only user-home
        expansion happens here.

        Args:
            value: The path as parsed so far.

        Returns:
            The path with any leading ``~`` expanded.
        """
        return Path(value).expanduser()

    @field_validator("contact", mode="before")
    @classmethod
    def _blank_contact_is_unset(cls, value: object) -> object:
        """Treat a blank or whitespace-only contact string as unset.

        ``MESHPROVISION_CONTACT=`` in ``.env`` is the documented shape of
        ``.env.example`` for "not configured yet"; this validator turns
        that into ``None`` so :meth:`require_contact` sees it as unset
        rather than as an empty, technically-present value.

        Args:
            value: The raw value supplied for ``contact``.

        Returns:
            ``None`` when ``value`` is a blank/whitespace-only string;
            otherwise ``value`` unchanged.
        """
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper(cls, value: object) -> object:
        """Normalize a log level string to stripped upper case.

        Args:
            value: The raw value supplied for ``log_level``.

        Returns:
            The stripped, upper-cased string when ``value`` is a string;
            otherwise ``value`` unchanged.
        """
        if isinstance(value, str):
            return value.strip().upper()
        return value

    def require_contact(self) -> str:
        """Return the operator contact string, raising when unset.

        Returns:
            The configured, non-blank contact string.

        Raises:
            MissingContactError: If :attr:`contact` is ``None``.
        """
        if self.contact is None:
            raise MissingContactError()
        return self.contact

    def user_agent(self, *, version: str | None = None, require_contact: bool = True) -> str:
        """Build the ``User-Agent`` string sent to lorastats.pl.

        Args:
            version: Package version to embed. Defaults to
                ``meshprovision.__version__``.
            require_contact: Whether a missing :attr:`contact` should
                raise. Set to ``False`` on paths that never query
                lorastats, where contact-bearing identification is not
                required.

        Returns:
            A string of the form ``"meshprovision/<version> (+<contact>)"``,
            or bare ``"meshprovision/<version>"`` when ``require_contact``
            is ``False`` and no contact is configured.

        Raises:
            MissingContactError: If :attr:`contact` is unset **and**
                ``require_contact`` is ``True`` -- this is the single
                startup gate lorastats.pl access requires.
        """
        if version is None:
            from meshprovision import __version__ as package_version

            version = package_version
        if not require_contact and self.contact is None:
            return f"meshprovision/{version}"
        contact = self.require_contact()
        return f"meshprovision/{version} (+{contact})"

    def with_overrides(self, **changes: object) -> Settings:
        """Return a new :class:`Settings` with the given fields replaced.

        The project's immutability convention: this never mutates
        ``self``. The copy is re-validated (not just shallow-copied) so
        an override that would violate a field constraint is caught
        immediately.

        Args:
            **changes: Field name/value pairs to replace.

        Returns:
            A new, independently validated :class:`Settings` instance.
        """
        copied = self.model_copy(update=changes, deep=False)
        return Settings.model_validate(copied.model_dump())


def find_env_file(start: Path | None = None) -> Path | None:
    """Locate the nearest ``.env`` file, searching upward from ``start``.

    Walks ``start`` and each of its parent directories, returning the
    first ``.env`` found. Deliberately does not use ``dotenv.find_dotenv``,
    which inspects the caller's stack frame and behaves unpredictably
    when called from within pytest.

    Args:
        start: Directory to begin searching from. Defaults to
            ``Path.cwd()``.

    Returns:
        The path to the nearest ``.env`` file, or ``None`` if none is
        found.
    """
    base = start if start is not None else Path.cwd()
    for directory in (base, *base.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return None


def load_settings(
    *,
    env_file: Path | str | None = None,
    environ: Mapping[str, str] | None = None,
    overrides: Mapping[str, object] | None = None,
    search_dotenv: bool = True,
) -> Settings:
    """Build a :class:`Settings` instance from ``.env``, the environment, and overrides.

    Layers, from lowest to highest precedence: values from a ``.env``
    file (explicit ``env_file``, or the nearest one found via
    :func:`find_env_file` when ``search_dotenv`` is true), then
    ``environ`` (defaulting to ``os.environ``), then ``overrides``.
    ``os.environ`` is never mutated.

    A blank value for any field (including ``MESHPROVISION_CONTACT=`` in
    ``.env``) is treated as "not set" rather than as an empty string,
    letting the field's own default (or lack of one) apply.

    A ``.env``/environment key that starts with :data:`ENV_PREFIX` but
    doesn't name a field in :data:`ENV_FIELD_MAP` (a typo, most often)
    is logged as a warning rather than silently ignored -- the affected
    field still falls back to its default either way, but the operator
    at least has a trail back to the cause.

    Args:
        env_file: An explicit ``.env`` file to read. When given, it is
            used instead of searching.
        environ: The environment mapping to read ``MESHPROVISION_*``
            variables from. Defaults to ``os.environ``.
        overrides: Explicit field overrides, highest precedence. A
            ``None`` value in this mapping is ignored rather than
            treated as an explicit override.
        search_dotenv: Whether to search for the nearest ``.env`` file
            when ``env_file`` is not given.

    Returns:
        A validated :class:`Settings` instance.

    Raises:
        SettingsError: If the layered values fail :class:`Settings`
            validation.
    """
    values: dict[str, str] = {}
    unrecognized: set[str] = set()
    if search_dotenv or env_file is not None:
        dotenv_path = Path(env_file) if env_file is not None else find_env_file()
        if dotenv_path is not None and dotenv_path.is_file():
            dotenv_values = dotenv.dotenv_values(dotenv_path)
            values.update({k: v for k, v in dotenv_values.items() if v is not None})
            unrecognized.update(
                k for k in dotenv_values if k.startswith(ENV_PREFIX) and k not in ENV_FIELD_MAP
            )

    source_environ = environ if environ is not None else os.environ
    values.update({k: v for k, v in source_environ.items() if k in ENV_FIELD_MAP})
    unrecognized.update(
        k for k in source_environ if k.startswith(ENV_PREFIX) and k not in ENV_FIELD_MAP
    )

    if unrecognized:
        _logger.warning(
            "Unrecognized %s variable(s), ignored: %s. See .env.example for every supported name.",
            ENV_PREFIX.rstrip("_"),
            ", ".join(sorted(unrecognized)),
        )

    data: dict[str, object] = {}
    for env_name, field in ENV_FIELD_MAP.items():
        raw = values.get(env_name)
        if raw is not None and raw.strip():
            data[field] = raw.strip()

    if overrides:
        data.update({k: v for k, v in overrides.items() if v is not None})

    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise SettingsError(
            format_validation_error(exc, source="environment/.env"),
            hint="See .env.example for every supported variable.",
        ) from exc


def format_validation_error(exc: ValidationError, *, source: str) -> str:
    r"""Render a pydantic :class:`ValidationError` as operator-readable text.

    Deliberately omits each error's ``input`` value: a template or
    environment value could be sensitive (a path containing a username,
    or worse), so nothing that was actually submitted is echoed back.

    Args:
        exc: The validation error to render.
        source: Human-readable description of what was being validated
            (a file path, or ``"environment/.env"``).

    Returns:
        A multi-line string: a header naming ``source`` and the problem
        count, followed by one indented ``field.path: message`` line per
        error.
    """
    lines = [f"{source} failed validation ({exc.error_count()} problem(s)):"]
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "<root>"
        lines.append(f"  {loc}: {err['msg']}")
    return "\n".join(lines)
