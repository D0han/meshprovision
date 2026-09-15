# Contributing to meshprovision

Thanks for considering a contribution. This project is a CLI provisioning
and monitoring toolkit for Meshtastic mesh nodes, and it holds itself to a
fairly strict bar on tests, typing, and security hygiene since it handles
admin key material. This document covers the contribution workflow; see
the [Development](README.md#development) section of the README for the
exact toolchain commands.

## Before you start

- For anything beyond a small fix (a new command, a schema change, a change
  to the admin-key or weak-key-audit logic), please open an issue first to
  discuss the approach. It saves rework on both sides.
- Check existing issues and open pull requests to avoid duplicate work.

## Setting up

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Run `pre-commit` from the same virtualenv you installed into -- the `mypy`
and `no-tracked-secrets` hooks are `language: system` and rely on the tools
already installed there. See the comments in `.pre-commit-config.yaml` if
you're curious why.

## Making a change

1. Create a branch off `main`.
2. Write the test first where practical. This project's own convention
   (see any recent commit) is: write a regression test that fails for the
   right reason, implement the fix, confirm the test passes, then verify
   the test is actually load-bearing by temporarily reverting the fix and
   confirming the test fails again before restoring it. That last step
   catches a test that looks right but doesn't actually exercise the bug.
3. Keep the change scoped. A bug fix doesn't need an accompanying
   refactor; a new command doesn't need speculative options nobody asked
   for.

## Before opening a PR

Run the same checks CI runs:

```bash
ruff check .
ruff format --check .
mypy --strict src
pytest --cov --cov-report=term-missing
```

- Coverage floor is 85% (`[tool.coverage.report] fail_under` in
  `pyproject.toml`); the suite currently sits well above it. A PR that
  drops the project below the floor won't pass CI.
- Tests are marked `unit` (fast, pure-logic, no I/O) or `e2e` (full CLI
  invocations against a fully mocked device/network/filesystem -- nothing
  in this suite ever touches a real serial port, BLE radio, or network
  endpoint). Add new tests to the matching directory (`tests/unit/` or
  `tests/e2e/`) and mark them accordingly.
- `mypy --strict` must pass with zero errors on `src/`. This project has
  no untyped functions and no `# type: ignore` used casually -- if you
  need one, leave a comment explaining why.
- If your change is user-visible, add a line to `CHANGELOG.md` under
  `## [Unreleased]`, in the appropriate `### Added` / `### Fixed` /
  `### Security` section, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
  style -- state what changed and, for a fix, what the prior (wrong)
  behavior was.

## Secret hygiene

This project handles X25519 admin key material and BLE pairing PINs.
Please keep to its existing convention:

- Raw key material must never appear in default CLI output, logs, or
  `--json` output -- only a `sha256:`-prefixed fingerprint
  (`meshprovision.crypto.redact.fingerprint`). The one deliberate
  exception is `mesh adopt --show-admin-keys`, and only for keys not
  already registered in the `Keys` sheet.
- The `detect-secrets` pre-commit hook and `tests/unit/test_no_tracked_secrets.py`
  both run automatically; don't disable or narrow them to get a commit
  through.
- If you find a security issue (not just a bug), please use GitHub's
  private vulnerability reporting for this repository rather than a
  public issue.

## Code style

- No comments explaining *what* code does when the code already says
  so -- explain *why* only when it's non-obvious (a workaround, an
  invariant, a firmware quirk). Look at existing docstrings for the tone.
- Prefer small, focused functions and modules over large ones; this
  project targets roughly 200-400 lines per file, with a handful of
  long-standing, deliberately-not-yet-split exceptions noted in the code
  itself.
- `ruff format` and `ruff check --fix` handle formatting and most style
  issues automatically -- run them before committing rather than
  hand-formatting.

## Regenerating generated files

- Example database: `python scripts/generate_example_db.py` (deterministic
  -- re-running it with no source changes should produce a byte-identical
  file).
- Weak-key blocklist: `python scripts/update_known_bad_keys.py --help`.

## Questions

Open an issue, or start a discussion if the repository has GitHub
Discussions enabled.
