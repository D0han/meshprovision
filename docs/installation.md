# Installation

Part of the meshprovision docs — see the [README](../README.md).

## Requirements

- Python >= 3.11, < 3.15 (CI matrix: 3.11, 3.12, 3.13).
- `meshtastic >= 2.7.11`, which already depends on `bleak`, so BLE needs
  no extra package.
- Linux is the tested platform (developed against Linux Mint). Serial
  access needs `dialout`/`plugdev` group membership; BLE needs BlueZ.
- A contact address for `MESHPROVISION_CONTACT` — mandatory, see
  [Configuration](configuration.md).

## From source

The only supported route today — this project is not published to PyPI:

```bash
git clone https://github.com/D0han/meshprovision.git
cd meshprovision
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Runtime-only install:

```bash
pip install -e .
```

BLE extra:

```bash
pip install -e ".[ble]"
```

This is a documented alias, kept so the command stays valid: upstream
`meshtastic` now depends on `bleak` directly, so BLE works without it.

Everything (`dev` + `ble`) in one shot:

```bash
pip install -e ".[all]"
```

## `pipx`

```bash
pipx install .
```

This installs the `mesh` script. If you already have a `mesh` on `PATH`:

```bash
pipx install --suffix=-mp .
```

installs it as `mesh-mp` instead.

**Name note:** the distribution is `meshprovision`; only the console
script is named `mesh`. It does not collide with the unrelated, abandoned
`mesh` distribution on PyPI, but `mesh` is short and generic, hence the
`pipx` rename tip above.

## Doing it by hand

Prefer to skip `mesh init`'s wizard? The two example files it copies live
at `src/meshprovision/examples/`:

```bash
cp src/meshprovision/examples/env.example .env
# edit .env, set MESHPROVISION_CONTACT
cp src/meshprovision/examples/template.example.yaml config/template.yaml
# edit config/template.yaml
mesh init --yes  # .env and the template are already there, so this only
                  # creates the (empty) database
```

See [Quick start](../README.md#quick-start) in the README for the normal,
wizard-driven path.
