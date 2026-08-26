"""The required CI guard: no sensitive filename pattern is ever tracked by git."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]

_EXACT_MATCHES = frozenset({"data/nodes_db.ods", "config/template.yaml"})
_BACKUP_DIR_PREFIX = "data/backups/"
_SUFFIX_DENYLIST = frozenset({".key", ".pem", ".log"})
_SEGMENT_DENYLIST = frozenset({".cache", "secrets", "logs"})


def tracked_files(root: Path) -> tuple[str, ...]:
    """Return every path tracked by git in ``root``, or skip if unavailable.

    Args:
        root: The repository root to inspect.

    Returns:
        Every tracked path, POSIX-style, relative to ``root``.
    """
    git_exe = shutil.which("git")
    if git_exe is None:
        pytest.skip("git is unavailable")
    result = subprocess.run(
        [git_exe, "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=False,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("git is unavailable")
    parts = result.stdout.split(b"\x00")
    return tuple(p.decode("utf-8") for p in parts if p)


def _matches_rule(path: str) -> str | None:
    """Return the name of the first matching offending-pattern rule, if any.

    Args:
        path: A POSIX-style repo-relative path.

    Returns:
        The rule name that flags ``path``, or ``None`` if it is allowed.
    """
    if path in _EXACT_MATCHES:
        return "exact_match"

    basename = path.rsplit("/", 1)[-1]
    if basename == ".env" or (basename.startswith(".env.") and basename != ".env.example"):
        return "dotenv"

    segments = path.split("/")
    if any(segment in _SEGMENT_DENYLIST for segment in segments):
        return "sensitive_directory_segment"

    if path.startswith(_BACKUP_DIR_PREFIX) and basename != ".gitkeep":
        return "backups_directory"

    for suffix in _SUFFIX_DENYLIST:
        if path.endswith(suffix):
            return "sensitive_suffix"

    if path.endswith(".ods.bak"):
        return "ods_backup_suffix"

    return None


def offending_paths(paths: Iterable[str]) -> tuple[tuple[str, str], ...]:
    """Return every ``(path, rule_name)`` pair that violates the secret-hygiene rules.

    Args:
        paths: Candidate repo-relative POSIX paths.

    Returns:
        A tuple of ``(path, rule_name)`` pairs for every offending path.
    """
    result: list[tuple[str, str]] = []
    for path in paths:
        rule = _matches_rule(path)
        if rule is not None:
            result.append((path, rule))
    return tuple(result)


def test_no_sensitive_files_are_tracked() -> None:
    offenders = offending_paths(tracked_files(REPO_ROOT))
    message = "\n".join(f"{path} (rule: {rule})" for path, rule in offenders)
    assert offenders == (), f"Sensitive files are tracked by git:\n{message}"


@pytest.mark.parametrize(
    "path",
    [
        "data/nodes_db.ods",
        "config/template.yaml",
        ".env",
        ".env.local",
        ".cache/x.json",
        "data/backups/nodes_db-20260101T000000Z.ods",
        "secrets/admin.key",
        "foo/bar.pem",
        "run.log",
        "logs/mesh.log",
        "data/nodes_db.ods.bak",
    ],
)
def test_matcher_flags_known_bad_paths(path: str) -> None:
    assert offending_paths([path]) != ()


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        "config/template.example.yaml",
        "data/nodes_db.example.ods",
        "data/known_bad_keys.txt",
        "data/backups/.gitkeep",
        "src/meshprovision/crypto/keys.py",
        "README.md",
    ],
)
def test_matcher_allows_expected_repo_paths(path: str) -> None:
    assert offending_paths([path]) == ()
