# meshprovision

Provisioning and read-only monitoring toolkit for Meshtastic mesh nodes on
the Polish (PL) mesh. It provisions devices from a template over
Serial/BLE/TCP, repairs configuration drift, tracks nodes and keys in a
real, hand-editable ODS spreadsheet meant to be opened and corrected in
LibreOffice — not hidden behind commands — and reports network health
from [loranet.pl](https://loranet.pl) and [lorastats.pl](https://lorastats.pl).

## What it does

- Template-driven provisioning of factory-fresh, already-provisioned, or
  foreign nodes over Serial, BLE, or TCP, with drift detection and repair:
  a connected node's live configuration is diffed against the template and
  the database, and only what has actually drifted is rewritten.
- Exact `--dry-run` plans and transactional writes — every config write is
  re-read and compared to intent, and key writes are additionally
  verified by reading the public key back off the device, before
  anything is recorded.
- X25519 key generation with `cryptography`, plus a layered
  CVE-2025-52464 weak-key audit run against every key already on file.
- Admin-key custody for 0-3 inbound admin nodes, with bootstrap and
  import paths and pending-cross-authorization reporting.
- A hand-editable ODS node database with real spreadsheet features:
  OpenFormula formulas for every derived column, dropdown validation,
  a frozen header row, and a free-form `notes` column that's yours
  alone — nothing in the project ever writes to it. A known-good safety
  copy is refreshed on every successful read or write, so a hand-edit
  gone wrong is always recoverable via `mesh db restore --known-good`.
- Strictly read-only network status reporting (`mesh status`), merging
  loranet.pl and lorastats.pl through a TTL disk cache.

## Requirements

- Python >= 3.11, < 3.15
- `meshtastic >= 2.7.11` (already depends on `bleak`, so BLE needs no
  extra package)
- Linux (developed and tested on Linux Mint)
- A contact address for `MESHPROVISION_CONTACT` (mandatory — see
  [Configuration](docs/configuration.md))

Full details: [Installation](docs/installation.md).

## Install

```bash
git clone https://github.com/D0han/meshprovision.git
cd meshprovision
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Runtime-only install, the `[ble]`/`[all]` extras, and `pipx` packaging are
covered in [Installation](docs/installation.md).

## Quick start

1. `mesh init` — prompts for your contact address, writes `.env`, copies
   the bundled provisioning template to `config/template.yaml`, and
   creates an empty `data/nodes_db.ods`. Safe to re-run. Any `mesh`
   command offers to do the same thing whenever setup is incomplete, so
   this step is optional but recommended first.
2. Edit `config/template.yaml` — at minimum `lora.region`, the name
   patterns, and `admin_nodes`. See the
   [template walkthrough](docs/configuration.md#template-walkthrough-configtemplateyaml).
3. `mesh db verify` — confirms the database loads, the schema validates,
   and the key rows pass the weak-key audit. Run it after any hand-edit;
   if it ever fails, `mesh db restore --known-good` undoes the edit.
4. `mesh provision --dry-run --port /dev/ttyUSB0` — prints the exact
   change plan without writing to the device or the database.

## Command cheat sheet

One console script, `mesh`, with seven subcommands/subcommand groups.
**Global options go before the subcommand** — `mesh --no-cache status
--json`, not `mesh status --no-cache`. Every command supports `-h`/`--help`.

| Command | What it does |
|---|---|
| `mesh init` | Create whatever first-run setup (`.env`, template, database) is still missing. |
| `mesh provision` | Provision a connected device from the template: connects, diffs, writes. |
| `mesh adopt` | Inventory an already-configured device — strictly read-only toward it. |
| `mesh status` | Read-only network health from loranet.pl/lorastats.pl, merged with the database. |
| `mesh admin` | Admin-key custody: `bootstrap`, `import`, `list`. |
| `mesh db` | Database integrity/backup: `verify`, `backup`, `restore`, `list`, `forget`. |
| `mesh template` | `validate` a template file — no database or device needed. |

The five commands you'll actually type most often:

```bash
mesh db verify                                  # sanity-check the database
mesh provision --dry-run --port /dev/ttyUSB0    # preview a plan, write nothing
mesh provision --port /dev/ttyUSB0 --yes        # provision for real
mesh adopt --port /dev/ttyUSB0                  # inventory an already-deployed device
mesh status --json                              # machine-readable network health
```

Every flag for every command is documented in [Commands](docs/commands.md).

## Documentation

| Doc | Covers |
|---|---|
| [Installation](docs/installation.md) | Requirements, source/`pipx` install, extras, the hand-copy setup path |
| [Configuration](docs/configuration.md) | Environment variables, full `config/template.yaml` walkthrough |
| [The node database](docs/database.md) | `Nodes`/`Keys` sheet schemas, `observed-*` rows, hand-editing tips, the shipped example |
| [Commands](docs/commands.md) | Every subcommand, every flag, exit codes |
| [Security](docs/security.md) | Key generation, the admin-key model, the CVE-2025-52464 weak-key audit, secret hygiene |
| [Firmware 2.8 and beyond](docs/firmware-compatibility.md) | What's fixed, blocked, or still an open risk as firmware and the `meshtastic` library evolve |
| [Design notes](docs/design-notes.md) | Deliberate deviations from the original specification |
| [Troubleshooting](docs/troubleshooting.md) | Linux Mint: USB serial, BLE, TCP/network issues |

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full contribution
workflow (branching, tests-first convention, PR checklist, secret
hygiene). The `quality` job's checks, kept character-identical with
`.github/workflows/ci.yml`:

```bash
pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy --strict src
pytest --cov --cov-report=term-missing --cov-fail-under=85
```

A separate `package` job builds the sdist/wheel (`python -m build`),
runs `twine check`, and smoke-tests the built wheel's console script
against all six subcommand groups. Locally, `pre-commit install` plus
`pre-commit run --all-files` covers the same lint/type/secret checks
before you push. Run `pre-commit` from the same virtualenv where you ran
`pip install -e ".[dev]"` — the mypy and no-tracked-secrets hooks are
`language: system` and use the tools already installed there.

Coverage floor is 85% (`[tool.coverage.report] fail_under`). CI runs the
3.11/3.12/3.13 matrix plus a package-build job.

Regenerate the example database: `python scripts/generate_example_db.py`.
Extend the weak-key blocklist: `python scripts/update_known_bad_keys.py --help`.

## License

MIT. See [`LICENSE`](LICENSE) (also declared in `pyproject.toml`).
