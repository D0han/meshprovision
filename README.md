# meshprovision

Provisioning and read-only monitoring toolkit for Meshtastic mesh nodes on
the Polish (PL) mesh. It provisions devices from a template over
Serial/BLE/TCP, repairs configuration drift, tracks nodes and keys in a
hand-editable ODS spreadsheet, and reports network health from
[loranet.pl](https://loranet.pl) and [lorastats.pl](https://lorastats.pl).

## Contents

- [What it does](#what-it-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [The node database (.ods)](#the-node-database-ods)
- [Commands](#commands)
- [Security](#security)
- [Deliberate deviations from the original specification](#deliberate-deviations-from-the-original-specification)
- [Troubleshooting on Linux Mint](#troubleshooting-on-linux-mint)
- [Development](#development)
- [License](#license)

## What it does

- Template-driven provisioning of factory-fresh, already-provisioned, or
  foreign nodes over Serial, BLE, or TCP.
- Drift detection and repair: a connected node's live configuration is
  diffed against the template and the database, and only what has
  actually drifted is rewritten.
- Exact `--dry-run` plans -- the planner (`provisioning/plan.py`) is pure,
  with no I/O, so the printed plan is exactly what would be applied, not
  an approximation of it.
- Transactional writes: every config write is re-read and compared to
  intent, and key writes are additionally verified by reading the public
  key back off the device, before anything is recorded.
- X25519 key generation with `cryptography`, plus a layered
  CVE-2025-52464 weak-key audit run against every key already on file.
- Admin-key custody for 0-3 inbound admin nodes, with bootstrap and
  import paths and pending-cross-authorization reporting.
- A hand-editable ODS node database with real spreadsheet features:
  OpenFormula formulas for every derived column, dropdown validation,
  and a frozen header row.
- Strictly read-only network status reporting (`mesh status`), merging
  loranet.pl and lorastats.pl through a TTL disk cache.

## Requirements

- Python >= 3.11, < 3.15 (CI matrix: 3.11, 3.12, 3.13).
- `meshtastic >= 2.7.11`, which already depends on `bleak`, so BLE needs
  no extra package.
- Linux is the tested platform (developed against Linux Mint). Serial
  access needs `dialout`/`plugdev` group membership; BLE needs BlueZ.
- A contact address for `MESHPROVISION_CONTACT` -- mandatory, see
  [Configuration](#configuration).

## Installation

From source (the only supported route today -- this project is not
published to PyPI):

```bash
git clone <your-fork-or-clone-url> meshprovision
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

`pipx`:

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

## Quick start

1. `cp .env.example .env` then edit `.env` and set `MESHPROVISION_CONTACT`
   to your own email address or URL. It ships EMPTY on purpose -- there is
   no default and a whitespace-only value is rejected at startup.
2. `cp config/template.example.yaml config/template.yaml` and edit it.
   Both the real template and the real database are gitignored.
3. `cp data/nodes_db.example.ods data/nodes_db.ods`
4. `mesh db verify` -- confirms the database loads, the schema validates,
   and the key rows pass the weak-key audit.
5. `mesh provision --dry-run --port /dev/ttyUSB0` -- prints the exact
   change plan without writing to the device or the database.

## Configuration

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `MESHPROVISION_DB_PATH` | `data/nodes_db.ods` | ODS node database (relative paths resolve against the CWD) |
| `MESHPROVISION_TEMPLATE_PATH` | `config/template.yaml` | Provisioning template |
| `MESHPROVISION_CACHE_DIR` | platformdirs user cache | HTTP TTL disk cache directory |
| `MESHPROVISION_CACHE_TTL` | `300` | Cache time-to-live, seconds |
| `MESHPROVISION_CONTACT` | (none -- REQUIRED) | Your contact address, sent in the `User-Agent` to lorastats.pl |
| `MESHPROVISION_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `MESHPROVISION_KNOWN_BAD_KEYS` | `data/known_bad_keys.txt` | Override path to the weak-key blocklist. Read directly by the crypto layer; not listed in `.env.example`. |
| `MESHPROVISION_LOCK_TIMEOUT` | `5.0` | Seconds a write command polls the database write lock before giving up. Not listed in `.env.example`; mainly useful for scripting against a slow/contended database. A value that is not a finite, non-negative number is rejected with exit 2 rather than silently ignored. |

Precedence, highest to lowest: **CLI flag > environment variable > `.env`
file > built-in default**. `.env` is found by searching upward from the
current working directory, or named explicitly with `--env-file`.

`MESHPROVISION_CONTACT` has no default because lorastats.pl requires
identifiable contact information in every request and bans IP addresses
that send missing, dummy, or third-party contact details -- a default
would make someone else wear your traffic.

### Template walkthrough (`config/template.yaml`)

The shipped `config/template.example.yaml` starts with:

```yaml
version: 1
```

Followed by module options:

```yaml
enabled_options: [telemetry, neighbor_info]
disabled_options: [mqtt, serial, range_test, store_forward, remote_hardware, paxcounter]
```

An option listed in *both* `enabled_options` and `disabled_options` is a
template-load error. An option meshprovision does not recognize is only a
warning, because firmware adds new modules over time.

Naming:

```yaml
short_name_pattern: "MT{n}{n}"
long_name_pattern: "Meshtastic MT{n}{n}"
name_suffix_alphabet: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
name_min_capacity: 100
name_capacity_warn_utilization: 0.9
name_capacity_strict: false
```

`{n}` is the only placeholder, and each occurrence consumes one character
from `name_suffix_alphabet`; write a literal brace as `{{`/`}}`.

**Hard limits, enforced at template-load time:** firmware **silently
truncates** an over-length name rather than rejecting it, so meshprovision
refuses to load a template whose *widest possible* rendering exceeds
**4 UTF-8 bytes** for `short_name` or **25 UTF-8 bytes** for `long_name`
(firmware 2.8 lowered `long_name` from 39 bytes; meshprovision now
enforces the tighter, 2.8-safe limit regardless of which firmware
version a given device runs).
These are byte limits, not character limits -- one accented or non-Latin
character can consume the entire 4-byte `short_name` budget on its own.

**Capacity** is `alphabet_size ** suffix_slots`. `MT{n}{n}` over the
base36 alphabet above is `36 ** 2 = 1296` names. `name_min_capacity: 100`
warns at load time if the pattern yields fewer names than that;
`name_capacity_strict: true` turns that warning into a hard load error;
`name_capacity_warn_utilization: 0.9` warns on every run once 90% of the
namespace is in use; exhaustion of the namespace is a clear error naming
the offending pattern.

Admin nodes:

```yaml
admin_nodes: []
```

0 to 3 entries, 3 being the firmware's `config.security.admin_key`
capacity. Each entry is a **label**, not a key, and must resolve to a
`<ref>_pub` row in the `Keys` sheet at provisioning time. meshprovision
appends `_pub`/`_priv`/`_psk` itself, so a ref must not already end in one
of those. An unresolvable ref is an error naming the ref and pointing at
`mesh admin bootstrap` / `mesh admin import`. Zero admins is a legitimate,
deliberate configuration and is never "repaired" toward three.

`device` (role: `CLIENT`), `lora`, `position`, `power`, and `telemetry`
blocks follow. Fields omitted from any of these blocks are left at the
device's current value rather than reset.

**Important, and worth calling out explicitly:**

```yaml
lora:
  region: EU_868
```

There is no "PL" region code in the Meshtastic protobuf, despite the
country code -- `EU_868` is the region used across Poland and most of the
EU. Do not confuse this with the lorastats `--region PL` path segment
used by `mesh status`, which is a completely different namespace: one is
a Meshtastic `RegionCode` protobuf value, the other is a URL path segment
on lorastats.pl. They are unrelated and both correct in their own
context -- this is a real trip hazard.

Finally, `security`:

```yaml
security:
  is_managed: false
  admin_channel_enabled: false
```

Key material **never** goes in this file -- a template containing
`private_key`, `public_key`, or `admin_key` is refused outright.
`is_managed: false` is lockdown mode; enabling it requires 1-3
`admin_nodes` **and** `--allow-lockdown` on the command line, plus the
safety gate described under [Security](#security). `admin_channel_enabled`
must stay `false` -- the legacy admin channel is never used anywhere in
this project.

## The node database (.ods)

The database is a real spreadsheet meant to be opened and edited in
LibreOffice, not a CSV dump.

### Nodes sheet

| Column | Kind | Notes |
|---|---|---|
| `node_id` | NODE_ID, primary key, required | 8 lowercase hex digits, no leading `!`; the same form lorastats.pl's `NodeId` field uses |
| `short_name` | TEXT | Device short name (<=4 bytes UTF-8), as sent to the node |
| `long_name` | TEXT | Device long name (<=25 bytes UTF-8, per firmware 2.8's tightened limit), as sent to the node |
| `hw_model` | ENUM (dropdown `mp_hw_model`) | Hardware model, from the installed `HardwareModel` protobuf enum |
| `main_chipset` | DERIVED, code-only | Main MCU/SoC for `hw_model`, derived by code (`meshprovision.chipsets.main_chipset`); not expressible as an ODF formula, so this column has no OpenFormula template |
| `firmware_type` | ENUM (dropdown `mp_firmware_type`) | Firmware flavor running on this node: `vanilla`, `loranet`, or `other` |
| `firmware_version` | TEXT | Firmware version string as reported by the device |
| `gps_lat` | FLOAT, `[-90, 90]` | Latitude in decimal degrees |
| `gps_lon` | FLOAT, `[-180, 180]` | Longitude in decimal degrees |
| `gps_alt` | INT | Altitude in meters |
| `first_added_ts` | TIMESTAMP (ISO-8601 UTC, e.g. `2026-08-25T03:14:10Z`) | UTC timestamp this node was first added to the database |
| `last_updated_ts` | TIMESTAMP | UTC timestamp this node's record was last updated |
| `authorized_admin_keys` | KEY_REF_LIST (`;`-separated) | Semicolon-separated `key_ref` list of admin public keys authorized on this node's `security.adminKey`. Deliberately **not** a formula: it records what was actually written to the device — narrowed when a run revokes a live admin key it names, but never rebuilt from the device, so a live key that was never recorded stays unrecorded — which is not a function of any other cell on the row |
| `notes` | TEXT | Free-form operator notes |
| `private_key_ref` | DERIVED, formula `=[.A{row}]&"_priv"` | Reference to this node's private key row in the `Keys` sheet |
| `public_key_ref` | DERIVED, formula `=[.A{row}]&"_pub"` | Reference to this node's public key row in the `Keys` sheet |
| `role` | ENUM (dropdown `mp_role`) | Device role, from the installed `Config.DeviceConfig.Role` protobuf enum |
| `region` | ENUM (dropdown `mp_region`) | LoRa region, from the installed `Config.LoRaConfig.RegionCode` protobuf enum |
| `channel_psk_ref` | DERIVED, formula `=[.A{row}]&"_psk"` | Reference to this node's channel PSK row in the `Keys` sheet |
| `ble_pin` | PIN, SECRET | 6-digit `bluetooth.fixed_pin`, stored as text so leading zeros survive; never logged or displayed |
| `management` | ENUM (dropdown `mp_management`) | `template` (the default; `mesh provision` enforces the template on this node) or `observed` (`mesh adopt` recorded this node's live state as-is; `mesh provision` refuses to touch it until `--enroll`). Empty reads back as `template`, so every pre-existing row keeps its current behavior |

### Keys sheet

| Column | Kind | Notes |
|---|---|---|
| `key_ref` | primary key, DERIVED | `owner_node_id` plus a suffix determined by `key_type` (`_pub`/`_priv`/`_psk`) |
| `owner_node_id` | KEY_REF, required | A node_id hex value, or a template `admin_nodes` label |
| `key_type` | ENUM (dropdown `mp_key_type`) | `admin_public`, `admin_private`, or `channel_psk` |
| `key_value` | BASE64_KEY, required, SECRET | Base64 of 32 raw X25519 bytes. Never logged or displayed |
| `created_ts` | TIMESTAMP | UTC timestamp this key was recorded |

### How the spreadsheet behaves

- **Formulas for everything derivable**, written with a cached display
  value so the file reads correctly before LibreOffice ever recalculates.
- **Derived columns are never authoritative.** On load, meshprovision
  recomputes each derived value from its sources and uses that, ignoring
  a stale cache. A disagreement logs a warning naming the cell -- which
  catches both a stale cache and a hand-edit that broke a formula.
- **Frozen header row** (split at row 1), sensible column widths, a bold
  header, and a long human description attached to each header cell as a
  comment.
- **Dropdowns** (`table:content-validation`) on every fixed-value column.
  LibreOffice treats validation as advisory, so the loader re-validates
  every value anyway and reports the offending sheet/row/column.

### Hand-editing tips

- Format `node_id` as Text (Format > Cells > Text) before typing. This is
  why the project uses `odfpy` directly and not `pandas`: a hex node id
  like `1234567e8` is otherwise parsed as a float in scientific notation,
  silently corrupting the primary key.
- Run `mesh db verify` after every hand-edit.
- `mesh db backup` before a risky edit; every save also writes a
  timestamped backup into `data/backups/` with a retention limit.

### The shipped example

`data/nodes_db.example.ods` ships three fake nodes:

- `deadbe01` / `MT01` / "Meshtastic MT01" / `HELTEC_V3` -- authorizes the
  `example-admin` admin key.
- `deadbe02` / `MT02` / "Meshtastic MT02" / `TRACKER_T1000_E`.
- `deadbe03` / `MT03` / "Meshtastic MT03" / `RAK4631` -- deliberately
  provisioned with **zero** admin keys, to show that is a valid outcome.

Keys: `deadbe01_pub`, `deadbe01_psk`, plus an `example-admin_pub` /
`example-admin_priv` pair.

Every key value is a 32-byte ASCII placeholder that spells out what it is
(base64-decode any cell and you get `EXAMPLE-KEY-DO-NOT-USE-000000001`),
so nobody can mistake it for live material -- and every placeholder still
passes the weak-key audit with zero findings, which the generator asserts
on each run.

Regenerate it with:

```bash
python scripts/generate_example_db.py
```

All timestamps are pinned to `2026-01-01T12:00:00Z`, so `Nodes`/`Keys`
content is byte-identical across runs; only the zip entries' own mtimes
vary.

## Commands

The toolkit installs **one** console script, `mesh`, with five subcommand
groups. **Global options go before the subcommand** -- for example
`mesh --no-cache status --json`, not `mesh status --no-cache`.

**Output contract:** STDOUT carries machine-readable output only
(`--json` documents, the `mesh status` table, and `--dry-run` change
lines); logging, prompts, warnings, and errors all go to STDERR -- so
`mesh status --json | jq .` never needs filtering.

### Global options

| Option | Meaning |
|---|---|
| `--log-level` | Logging verbosity (default: `MESHPROVISION_LOG_LEVEL`, else `INFO`) |
| `--db-path` | Override the ODS node database path |
| `--template-path` | Override the provisioning template path |
| `--cache-ttl` | HTTP response cache time-to-live, in seconds |
| `--no-cache` | Bypass cache reads; responses are still written back to the cache |
| `--force-refresh` | Alias for `--no-cache` |
| `--non-interactive` / `--interactive` | Turn every prompt into an error |
| `--env-file` | Explicit `.env` file to read instead of searching upward from the CWD |
| `--version` | Print the version and exit |
| `-h`, `--help` | Show help and exit |

`--non-interactive` is auto-enabled whenever stdin is not a TTY, and it
turns every prompt into an error -- which is what makes `mesh` cron-safe.

### `mesh provision`

Connects over Serial/BLE/TCP, classifies the node as `FACTORY` /
`PROVISIONED` / `FOREIGN`, builds and prints an exact change plan, and
(unless `--dry-run`) applies it and records the result.

**Transport selection priority:** `--port` > `--ble-address`/`--ble-scan`
> `--host` > auto (serial first; exactly one port is auto-used, zero
ports offers BLE then a TCP host prompt, several ports prompts).
`--interface {serial,ble,tcp}` forces a mode and makes ambiguity a hard
error instead of a prompt.

```bash
mesh provision --dry-run --port /dev/ttyUSB0
mesh provision --port /dev/ttyUSB0 --yes
mesh provision --interface tcp --host 192.168.1.50
mesh provision --ble-scan --ble-scan-timeout 15
mesh provision --interface serial --port /dev/ttyACM0 --rename
mesh provision --port /dev/ttyUSB0 --force-regenerate-key
mesh provision --port /dev/ttyUSB0 --allow-lockdown
mesh provision --dry-run --interface tcp --host 192.168.1.50 --json
mesh provision --port /dev/ttyUSB0 --enroll
```

| Option | Meaning |
|---|---|
| `--timeout` | Connect timeout, in seconds |
| `--ble-scan-timeout` | BLE scan duration, in seconds |
| `--dry-run` | Print the plan without writing anything |
| `-y`, `--yes` | Assume yes to every confirmation |
| `--enroll` | Bring an observed (`mesh adopt`-recorded) node under template management |
| `--allow-lockdown` | Explicitly authorize enabling `security.is_managed` when the safety gates pass |
| `--allow-weak-admin-key` | Authorize admin keys that fail the weak-key audit; does not relax the `security.is_managed` safety gate |
| `--force-regenerate-key` | Regenerate the node keypair unconditionally |
| `--rename` | Allow renaming an already-provisioned node |
| `--no-reconnect` | Verify writes against the in-memory interface only (weaker guarantee) |
| `--json` | Emit JSON instead of human text |

`--no-reconnect` is a deliberately **weaker** guarantee: writes are
verified against the in-memory interface only. The default reconnects and
re-reads, because of firmware issue #7449 (a restored private key could
be discarded on reboot, with the device regenerating fresh keys).

A node whose `Nodes` sheet row has `management=observed` (recorded by
`mesh adopt`, below) is refused with exit code 5 unless `--enroll` is
passed -- checked before any admin-key resolution runs, and before
`--dry-run`'s early return, so an unenrolled node never even reaches a
plan preview it didn't ask for. `mesh admin bootstrap` inherits the same
gate, since it drives this same pipeline. `--enroll` graduates the row to
`management=template` on a successful apply; it is a one-time flag --
once enrolled, ordinary `mesh provision` runs need it again.

**Transactional guarantee:** after each `writeConfig(section)` the config
is re-read and compared to intent; key writes are additionally verified
by reading the public key back off the device. Any unconfirmed write
marks the node `UNCERTAIN`, leaves the ODS **unchanged**, logs a warning,
and exits non-zero.

**Concurrent-write guarantee:** writers (`mesh provision`, `mesh admin
bootstrap`/`import`) take an exclusive lock on `<db>.lock` for the whole
load-modify-save cycle, including the device conversation and any
confirmation prompt. `mesh db backup` deliberately takes no lock: it
copies the raw file with `shutil.copy2`, which reads the inode it opened
through to completion even if a concurrent writer replaces the path
mid-copy, so a backup is always a complete snapshot of one version of
the database. A second write command that cannot acquire the lock
within `MESHPROVISION_LOCK_TIMEOUT` seconds (default 60, sized for a
full multi-section device transaction rather than just the save) fails
fast with exit code 4 and a message naming the holder's pid when known,
rather than silently discarding whichever write loses the race. Read-only
commands (`mesh status`, `mesh db verify`, `mesh db backup`) are never
blocked by it. `--dry-run` does not take the lock. POSIX only: on a
platform without `fcntl` the lock is a no-op, logged once at WARNING.

### `mesh adopt`

For a node that is already configured and already in service -- the
normal case for an existing fleet you're bringing into meshprovision for
the first time. Connects the same way `mesh provision` does, but is
**strictly read-only toward the device**: it never calls `writeConfig`,
never diffs against the template, and never renames, reconfigures, or
regenerates anything on the node. It records the device's actual live
state -- names, admin keys, firmware version, region, role, BLE PIN --
into the database as `management=observed`, so `mesh provision` leaves
it alone until you explicitly decide otherwise with `--enroll`.

```bash
mesh adopt --port /dev/ttyUSB0
mesh adopt --dry-run --interface tcp --host 192.168.1.50
mesh adopt --port /dev/ttyUSB0 --yes --show-admin-keys
mesh adopt --port /dev/ttyUSB0 --force
```

| Option | Meaning |
|---|---|
| `--dry-run` | Print the report without writing to the database |
| `-y`, `--yes` | Assume yes to every confirmation |
| `--json` | Emit JSON instead of human text |
| `--force` | Re-adopt (demote) a node that is currently `management=template` |
| `--show-admin-keys` | Print paste-ready `mesh admin import` commands for admin keys the device reports that aren't in the `Keys` sheet |

An admin key already on the device but not yet in your `Keys` sheet --
for example a trusted friend's admin key, whose private half you never
hold and never need to -- is reported by fingerprint only by default,
never its raw material. `--show-admin-keys` is the one deliberate,
narrow exception to that rule: it prints the actual base64 so you can
register it yourself with `mesh admin import <REF>=<base64>`, choosing
your own meaningful ref (e.g. `FRIEND`). `mesh adopt` never invents a ref
or writes a `Keys` sheet row on your behalf.

Re-adopting an already-`observed` node **replaces** `authorized_admin_keys`
with exactly what's currently live -- unlike `mesh provision`'s
narrow-only rule for a template-managed row, an observed row has no
desired state to preserve against, so it mirrors reality every time,
including dropping a ref for a key that's no longer on the device.
Re-adopting a `management=template` row is refused unless `--force` is
passed, and the confirmation prompt names the demotion explicitly.

**Typical workflow for an existing fleet:**

```bash
mesh adopt --port /dev/ttyUSB0                    # record what's actually there
mesh admin import FRIEND=<base64-from-the-report>  # only if it reports an unregistered key you want to keep
mesh provision --port /dev/ttyUSB0 --enroll        # only when you're ready for template enforcement
```

The last step is optional and per-node -- a fleet can stay `observed`
indefinitely; `mesh status` and `mesh db verify` work the same either way.

### `mesh status`

Strictly read-only -- it never writes to the database or to any device.
That is enforced by code and by an e2e test that asserts the `.ods`
file's mtime is unchanged across a full status run.

Data sources: loranet.pl's bulk `https://loranet.pl/nodes.json` dump
(preferred for telemetry) and lorastats.pl per-node queries (last-seen
corroboration); most recent wins. Default thresholds: online < 2 h, stale
< 24 h, offline beyond.

```bash
mesh status
mesh status --json
mesh status --node deadbe01 --node '!a0cb5cc4'
mesh status --source loranet
mesh status --region PL
mesh status --stale-after 1 --offline-after 12
mesh status --watch --interval 60
mesh --no-cache status --json
mesh status --no-fail-on-offline
```

The rendered table columns are: Node, Short, Long, Mgmt, Status, Last seen,
Timestamp, Batt, Volt, ChUtil, AirTx, Nbrs, Sources.

`--watch` respects the cache TTL (default poll interval = the cache TTL,
floored at 5 s) and prints a per-poll cache hit/miss/request line to
stderr.

`--fail-on-offline` is **on by default**: an offline node, or any source
failure, exits `7`. Pass `--no-fail-on-offline` to suppress that.

**Cache note:** every outbound request goes through the TTL disk cache; a
second run inside the TTL performs zero network calls. `--no-cache` /
`--force-refresh` bypasses reads but still writes the response back.

### `mesh admin`

No node can be provisioned as managed until some admin's public key
already exists in the `Keys` sheet -- that chicken-and-egg problem has two
first-class solutions.

```bash
mesh admin bootstrap --port /dev/ttyUSB0 --ref ADMIN1
mesh admin bootstrap --interface tcp --host 192.168.1.50 --ref ADMIN2 --dry-run
mesh admin import ADMIN3=<base64 32-byte public key>
mesh admin import ADMIN1=<b64> ADMIN2=<b64> --json
mesh admin import ADMIN3=<b64> --dry-run
mesh admin list
mesh admin list --json
```

- `bootstrap` provisions the connected node **and** registers it as an
  admin: generates its keypair, writes it to the device, records it in
  both sheets, and authorizes whichever admins already exist. Run it once
  per admin node. Later admins are authorized on earlier ones only when
  those devices are next connected -- the run **reports** which
  cross-authorizations are still pending rather than silently skipping
  them. It reuses `run_provision` wholesale, so it accepts and honors
  every option in `mesh provision`'s table above (`--dry-run`, `--enroll`,
  `--allow-lockdown`, `--allow-weak-admin-key`, `--force-regenerate-key`,
  `--no-reconnect`, `-y`/`--yes`, `--json`) in addition to its own `--ref`.
- `import` registers a public key you already hold, without touching a
  device. It validates length and canonical base64, runs the weak-key
  audit, and refuses a key already registered under a different reference
  unless `--force`. `--dry-run` runs every one of those checks and
  reports the outcome (including a refusal) without registering
  anything, matching `provision`/`adopt`/`admin bootstrap`'s existing
  `--dry-run` convention.
- `list` shows each admin's ref, whether the public key is present, a
  redacted fingerprint, whether the private counterpart is on hand,
  whether it is in the template, which node it resolves to, its weak-key
  audit result (`-` when no key is present, else `clean`, `warning`, or
  `compromised`), which nodes authorize it, and which authorizations are
  pending. Exits `2` if a
  template-listed admin is missing from the `Keys` sheet.

A REF is a label, never a key, and must not end in `_pub`/`_priv`/`_psk`.

### `mesh db`

```bash
mesh db verify
mesh db verify --strict
mesh db verify --json
mesh db backup
mesh db backup --list
mesh db backup --retention 20 --backup-dir /mnt/usb/mesh-backups
mesh db restore data/backups/nodes_db-20260101T000000.000000Z.ods
mesh db list
mesh db list --json
```

| Option | Meaning |
|---|---|
| `--strict` (`verify`) | Treat a bare warning (no error or critical problem) as a failing exit code too |
| `--backup-dir` (`backup`, `restore`) | Directory backups are stored under/read from. Defaults to `data/backups` |
| `--retention` (`backup`) | Number of backups to retain (default: 20) |
| `--list` (`backup`) | List existing backups instead of creating one |
| `-y`/`--yes` (`restore`) | Assume yes to the overwrite confirmation |
| `--json` | Emit JSON instead of human text |

- `verify` layers cross-reference checks, a weak-key audit over every key
  row, and alias-aware cross-fleet duplicate detection on top of the
  schema validation that already happens at load. Because `mesh admin
  bootstrap --ref LABEL` deliberately files one physical node's key under
  both `<node_id>_pub` and `<LABEL>_pub`, a duplicate group is
  **critical** only when it spans two or more **distinct real nodes** --
  the CVE-2025-52464 vendor key-cloning signature. A node-plus-label
  group is an informational alias warning.
- `backup` writes only into the backup directory and never rewrites the
  database itself.
- `restore` is the only `db` subcommand that rewrites the live database
  directly, so unlike `backup` it holds the cross-process write lock for
  the whole operation, excluding a concurrent `mesh provision`/`mesh
  admin` run. The current database is itself backed up first, so a
  restore is always reversible via `mesh db backup --list`. The restored
  file is loaded back immediately to confirm it is actually valid --
  restoring a corrupt or non-ODS file fails loudly on the spot rather
  than breaking the next unrelated `mesh` command.
- `list` is the offline counterpart to `mesh status`: a plain dump of the
  `Nodes` sheet's own content (short/long name, hardware model, firmware,
  management mode, region, role, authorized admin key refs, notes) --
  no device connection, no `MESHPROVISION_CONTACT`, no network round
  trip.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | ERROR (unexpected) |
| 2 | CONFIG |
| 3 | DATASOURCE |
| 4 | DB |
| 5 | PROVISIONING |
| 6 | CRYPTO |
| 7 | STATUS_DEGRADED |
| 130 | INTERRUPTED |

(From `meshprovision.errors.ExitCode`.)

Exit code 4 (`DB`) now also covers "another mesh command is running": a
write command that could not acquire the database's write lock within
`MESHPROVISION_LOCK_TIMEOUT` raises `DatabaseLockedError`, distinct from
the pre-existing `AtomicWriteError` raised on a filesystem failure
(read-only filesystem, missing parent) while creating the lock file
itself -- both share exit code 4, since the message text is the intended
disambiguation channel between them, not the exit code.

Exit code 5 (`PROVISIONING`) also covers two `mesh adopt`/`--enroll`
refusals: `NodeNotEnrolledError` (a `management=observed` node touched by
`mesh provision` without `--enroll`) and `AdoptionRefusedError` (a
`management=template` node re-adopted without `--force`) -- again
disambiguated by message text, not exit code.

## Security

### Key generation

`X25519PrivateKey.generate()` from `cryptography` -- exactly what the CVE
advisory itself recommends (`openssl genpkey -algorithm x25519 -outform
DER | tail -c32`). 32 raw bytes private + 32 public, stored base64 in the
`Keys` sheet, matching the `base64:` convention the Meshtastic CLI uses in
its own export format. Factory keys are treated as compromised and
regenerated.

### Write verification

Every config write is re-read and compared to intent; key writes are
verified by reading the public key back off the device (firmware issue
#7449). An unconfirmed write leaves the ODS untouched and exits non-zero.

### The admin-key model

Inbound only. The template's `admin_nodes` public keys are resolved from
the `Keys` sheet and written into the target's `config.security.admin_key`
(Python API: `security.adminKey`) -- a `repeated bytes` field, capacity 3.

`admin_channel_enabled` is forced to `false`; the legacy admin channel is
never used anywhere in this project.

`is_managed` stays `false` unless the template opts in, **and** the
safety gate passes. The gate refuses lockdown unless all three hold:

(a) at least one authorized admin key has its **private** counterpart in
    the `Keys` sheet,
(b) none of the admin keys fail the weak-key audit,
(c) `--allow-lockdown` was passed explicitly.

The weak-key check in (b) is **not** lockdown-only. On every run,
regardless of `is_managed`, an admin key from `admin_nodes` that fails
the weak-key audit is excluded from the desired `admin_key` set, so
ordinary provisioning never writes a compromised admin key to a device.
Lockdown adds a stricter reaction on top of that exclusion: under
`is_managed=true`, a failing admin key hard-refuses the **whole run**
rather than quietly dropping the key.

`--allow-weak-admin-key` is deliberately asymmetric about those two
behaviors. It overrides the plan-level exclusion, letting an operator
authorize a flagged key on an unlocked device; it never overrides the
lockdown refusal. A device can never be sealed with `is_managed=true`
while a compromised admin key is authorized, flag or no flag.

One hard interlock on top: `is_managed=true` with **zero** authorized
admin keys is refused outright -- that combination locks the node with
nobody able to administer it.

### CVE-2025-52464 and the weak-key audit

**"Repeated Public/Private Keypairs"**, CVSS 9.5, affects firmware
`>= 2.5.0` and `< 2.6.11`. Two root causes -- vendor mass-flashing cloned
identical keypairs across devices, and an improperly seeded RNG pool on
some platforms. Impact includes decrypting DMs and impersonating a remote
administrator, which is precisely this project's threat model. Fixed in
2.6.11; 2.6.12 wipes known compromised keys.

The audit is layered; any hit marks the node `COMPROMISED` and forces
regeneration:

| Check | What it catches |
|---|---|
| `all_zero`, `small_order`, `repeated_byte`, `monotonic`, `low_entropy`, `unclamped` | Structural checks on the key bytes |
| `consistency` | Recompute the public key from the private key and compare with what the device reports; a mismatch means corruption or a partial restore |
| `firmware_window` | A node reporting firmware in `[2.5.0, 2.6.11)` is treated as **presumptively compromised** regardless of the key's contents |
| `duplicate` | The public key matches another key in your own `Keys` sheet; two of your nodes sharing a public key is the vendor-cloning bug; reported CRITICAL |
| `blocklist` | The key appears in `data/known_bad_keys.txt` |

### What `data/known_bad_keys.txt` does and does NOT cover

- It does **not** contain the keypairs affected by CVE-2025-52464. **No
  such list has ever been published.** This was verified during planning
  by enumerating the complete file trees of `meshtastic/firmware` and
  `meshtastic/Meshtastic-Android` and by reading `NodeDB.cpp` and
  `CryptoEngine.cpp` at tag `v2.6.12.9861e82`: the firmware's only
  duplicate detection is the on-mesh advertisement check in `NodeDB.cpp`
  ("Remote device has advertised your public key"), and the advisory
  itself publishes no blocklist. The "compares against a hash of known
  duplicates" claim in secondary reporting corresponds to nothing in the
  source. Publishing such a list would also mean publishing live private
  keys for nodes still in the field.
- What **is** in it: the 7 canonical X25519 small-order / degenerate
  public points from libsodium's `has_small_order()` blocklist in
  `crypto_scalarmult/curve25519/ref10/x25519_ref10.c` -- the all-zero
  point, `0x01`-then-zeros, the two order-8 points, and `p-1` / `p` /
  `p+1` (`p = 2**255-19`). Each carries a provenance comment, so the file
  is auditable rather than a magic list. The same 7 values are also
  compiled into `crypto/weakkeys.py:SMALL_ORDER_POINTS`, so they still
  apply if the file is absent.
- The file was deliberately **not** padded with invented entries. A
  padded blocklist gives false assurance, which is worse than an honest
  short one.
- Therefore your effective controls against CVE-2025-52464 are the
  firmware-version window check and cross-node duplicate detection across
  your own `Keys` sheet -- **not** this file.
- Format and extension path: base64, one key per line, `#` comments. If
  the community ever publishes a real list, merge it with no code change:

  ```bash
  python scripts/update_known_bad_keys.py --source new_keys.txt --comment "provenance"
  ```

  (also supports `--dry-run` and `--check`). Public keys only -- never
  feed it private key material. Override the file's location with
  `MESHPROVISION_KNOWN_BAD_KEYS`.

### Firmware 2.8 and beyond

Firmware 2.8 ([release notes](https://github.com/meshtastic/firmware/releases/tag/v2.8.0.47db0e3))
makes several changes worth tracking here. As of this writing, the `meshtastic`
Python library this project depends on is still at **2.7.11 on PyPI** --
the same version pinned in `pyproject.toml` -- so anything below that needs
a newer protobuf schema than 2.7.x defines is **not yet something
meshprovision can read or write**, regardless of what changes here. What
follows is a record of what's known, what's already fixed, and what's
deliberately not guessed at.

**Fixed already:** `long_name`'s enforced limit dropped from 39 to 25 UTF-8
bytes. This needed no protobuf change -- it's a validation constant in this
project, not a device-reported field -- so `LONG_NAME_MAX_BYTES` is now 25
regardless of which firmware a given device runs. A name that fits in 25
bytes always fit in the old 39-byte limit too, so this is a pure tightening,
not a behavior change for anyone still on 2.7.x.

**Informational, no code change needed:** new US nodes now default to the
`LongTurbo` modem preset instead of `LongFast`, and the two presets cannot
hear each other. meshprovision has no opinion on modem preset defaults --
it applies whatever `lora.modem_preset` your template specifies -- so this
doesn't affect correctness, but if you're provisioning new nodes onto an
existing US mesh, check your template names the preset your mesh actually
uses rather than relying on the device's own factory default.

**Blocked pending a `meshtastic` library update, not yet actionable:** new
LoRa regions (70cm/1.25m/2m amateur bands, EU region consolidation), new
modem presets (`TinyFast`/`TinySlow`), XEdDSA packet-signing configuration,
and the licensed-operator rebroadcast restriction are all new or changed
protobuf fields that the currently-pinned library version has no definitions
for. meshprovision reads region/role/hw_model from whatever enum tables the
*installed* `meshtastic` package's protobufs expose (`enums.py`), so once a
2.8-compatible release lands on PyPI and the dependency floor is raised,
these should mostly appear automatically without code changes here -- but
that's untested until such a release exists, and this project's own
practice (see the CVE-2025-52464 section above) is to verify against real
source or a real device before claiming compatibility, not assume it.

**Found during research, deliberately not acted on yet -- a real risk to
the weak-key remediation workflow:** firmware 2.8 derives a node's number
from its public key rather than its MAC address, specifically "to minimize
the ability of an attacker to spoof a User packet from an existing nodenum
with a new public key," and firmware has a companion fix that refuses to
update a NodeDB entry when a received `NodeInfo` reports a public key that
doesn't match what's already on file for that node number (see
[`meshtastic/firmware` discussion #5007](https://github.com/meshtastic/firmware/discussions/5007)
and the linked implementation notes). The stated design is backwards
compatible for already-provisioned nodes -- existing node numbers aren't
expected to change on upgrade. But this project's `--force-regenerate-key`
workflow does exactly what that anti-spoofing check is designed to catch:
it legitimately rotates a node's own public key in place, under the same
node number, when the weak-key audit flags it as compromised. If other mesh
peers already have that node cached with its old (compromised) key, this
firmware behavior may make them refuse the new key on the next broadcast --
potentially leaving other nodes trusting a key you've just revoked, until
they're individually made to forget and re-learn it. This is a mesh-wide
security property meshprovision cannot see or control from a single
provisioning connection, and it has not been verified against a real
2.8 device or an updated library -- it's recorded here as a known,
unresolved risk to revisit once real 2.8 tooling exists, not as something
this project has (or could yet) fix.

### Secret hygiene

- Nothing raw is ever logged or printed. Secrets are wrapped in
  `SecretBytes`, whose `repr`/`str` render `<redacted:sha256:ab12...>`,
  and a structlog processor scrubs event dicts as the last step before
  rendering. A unit test asserts no raw key material reaches log output.
- Tracebacks use a plain formatter, never rich's `show_locals=True`, so a
  crash cannot dump local variables holding key bytes into the log.
- The 6-digit BLE PIN is treated as a secret like any other.
- `mesh adopt`'s `--show-admin-keys` is the one deliberate, narrow
  exception: it prints raw base64 public key material, and only for an
  admin key the device reports that isn't yet in the `Keys` sheet. It is
  off by default; without it, an unregistered admin key is reported by
  fingerprint only, in both human and `--json` output.

### Sensitive vs example files

| Path | Tracked in git? | What it is |
|---|---|---|
| `.env.example` | tracked | Variable names only, no values. `MESHPROVISION_CONTACT` ships empty. |
| `.env`, `.env.*` | IGNORED | Your real environment, including your contact address |
| `config/template.example.yaml` | tracked | Example template, generic `MT{n}{n}` naming |
| `config/template.yaml` | IGNORED | Your operational template |
| `data/nodes_db.example.ods` | tracked | Fake nodes, ASCII placeholder "keys" |
| `data/nodes_db.ods` | IGNORED | Your real database -- contains live private keys and BLE PINs |
| `data/backups/` | IGNORED (except `.gitkeep`) | Timestamped database backups |
| `data/known_bad_keys.txt` | tracked | Public small-order X25519 points; no private material |
| `.cache/` and the platform cache dir | IGNORED | HTTP TTL response cache |
| `*.key`, `*.pem`, `secrets/`, `*.log`, `logs/`, `*.ods.bak` | IGNORED | Never commit |

This is enforced by three independent layers: (1) `.gitignore`, (2) the
`detect-secrets` pre-commit hook, and (3)
`tests/unit/test_no_tracked_secrets.py`, which shells out to
`git ls-files` and fails CI if any sensitive pattern is ever tracked,
catching `git add -f` bypasses that `.gitignore` alone would miss.

## Deliberate deviations from the original specification

Each of these was confirmed with the project owner during planning and is
documented here rather than buried.

1. **`security.adminKey`, not `adminKeyAuthorized`.** The admin-key
   protobuf field is `config.security.admin_key` (`repeated bytes`, field
   3), exposed by the Python API camelCase as `adminKey`. There is no
   `adminKeyAuthorized` field. `SecurityConfig` also carries
   `admin_channel_enabled` (field 8) and `is_managed` (field 4).
2. **The region list is static and config-overridable, never
   auto-discovered.** No JSON endpoint for it exists --
   `/API/Regions/JSON` returns the HTML API page and `/Regions` is an
   HTML map. Discovering regions would require scraping, which
   lorastats.pl explicitly forbids and bans IP addresses for. Default:
   `["PL"]`.
3. **lorastats is queried per node via `?node=<hex>`, not by bulk region
   dump.** `?node=` is a server-side filter that turns a 1.8 MB region
   dump into a ~150 byte response. Related hardening: the region path
   segment is **not** validated server-side
   (`/API/NotARealRegion123/Nodes/JSON` returns the same data with HTTP
   200), and invalid paths elsewhere also return HTML with HTTP 200 -- so
   the datasource asserts the body actually parses as JSON and never
   trusts the status code.
4. **`odfpy` directly, not `pandas`.** pandas type-coerces cells, and a
   hex node id like `1234567e8` is silently parsed as a float in
   scientific notation, corrupting the primary key. Every cell is read
   and written as an explicit string. It also avoids a ~50 MB dependency
   for a sheet holding a few dozen rows.
5. **The `[ble]` extra is a documented alias.** Upstream `meshtastic`
   `>= 2.7.11` depends on `bleak` directly, so BLE works without an
   extra; the extra is kept so `pip install "meshprovision[ble]"` stays a
   valid, non-broken command.
6. **`is_managed` defaults to `false`, with a safety gate.** Writing
   `adminKey` plus `admin_channel_enabled=false` still happens; opting
   into lockdown requires the three-part gate described under
   [Security](#security).
7. **The example naming pattern is the generic `MT{n}{n}` (1296
   names)**, not the specification's `D0h{n}`, which the 4-byte
   `short_name` cap would have limited to 36 nodes. "MT" is short for
   Meshtastic -- a deliberately non-personal prefix. Fully configurable;
   the validator is what keeps a custom pattern honest.
8. **A single `mesh` console script with subcommands**, replacing the
   specification's two `meshprovision-*` executables (which stuttered).
   The read-only guarantee of `mesh status` is preserved by code and by
   test, not by binary separation.
9. **`data/known_bad_keys.txt` is committed but holds only the 7 verified
   X25519 small-order points** -- **no public CVE-2025-52464 key list
   exists**. Documented rather than padded with invented entries. See the
   [Security](#security) section.

## Troubleshooting on Linux Mint

### USB serial

- Check what you have: `ls -l /dev/ttyUSB* /dev/ttyACM*`, `lsusb`,
  `dmesg -w` while plugging the device in.
- The device node is group-owned by `dialout` (CH340/CP210x/FTDI adapters
  appear as `/dev/ttyUSB*`, native-USB boards such as nRF52/RP2040 as
  `/dev/ttyACM*`). Add yourself:

  ```bash
  sudo usermod -aG dialout,plugdev "$USER"
  ```

  Then **log out and back in** -- group membership is only picked up on a
  new login session. `newgrp dialout` works for the current shell only.
  Verify with `id -nG`.
- **brltty steals CH340/CH341 adapters.** On Mint/Ubuntu/Debian the
  `brltty` braille-display daemon claims those USB IDs, so `/dev/ttyUSB0`
  appears and then vanishes a second later. Confirm in `dmesg` /
  `journalctl -u brltty`, then either `sudo apt remove brltty` or mask
  its udev rule (`/usr/lib/udev/rules.d/85-brltty.rules`).
- **ModemManager probes new serial ports** and can hold the port for the
  first several seconds after plug-in. If connects fail intermittently
  right after plugging in, `sudo systemctl stop ModemManager` (or add a
  udev rule with `ENV{ID_MM_DEVICE_IGNORE}="1"`) and retry.
- Inspect the device with udev:

  ```bash
  udevadm info --name=/dev/ttyUSB0 --attribute-walk | head -40
  udevadm info --query=property --name=/dev/ttyUSB0
  udevadm monitor --udev --subsystem-match=usb
  ```

  The `ID_VENDOR_ID` / `ID_MODEL_ID` properties are the VID/PID that
  meshprovision's serial discovery matches on.
- List ports the way the toolkit does: `python -m serial.tools.list_ports -v`.
- Skip discovery entirely when in doubt:
  `mesh provision --interface serial --port /dev/ttyUSB0`.

### BLE

- Requires BlueZ (Mint ships it) and a running D-Bus session. Check:
  `systemctl status bluetooth`, `bluetoothctl show`, `rfkill list
  bluetooth` (unblock with `rfkill unblock bluetooth`).
- Scan independently of meshprovision: `bluetoothctl` then `scan on`.
- `meshtastic >= 2.7.11` depends on `bleak` directly -- no extra needed.
- Pairing uses the 6-digit fixed PIN stored in the `ble_pin` column of
  the `Nodes` sheet. To re-pair after a key change:
  `bluetoothctl remove <MAC>` then reconnect.
- Scans are slow on some adapters; raise `--ble-scan-timeout 15`.
- `mesh provision --interface ble --ble-address <MAC>` skips the scan.
- If scanning returns nothing as a normal user, confirm the `bluetooth`
  group / BlueZ policy allows it, and that no other tool (a phone app,
  another `bluetoothctl` session) currently holds the device -- a
  Meshtastic node accepts only one BLE client at a time.

### TCP / network

- Meshtastic's TCP API listens on port 4403. Test reachability first:
  `nc -vz 192.168.1.50 4403` or `ping 192.168.1.50`.
- `--host` accepts `HOST` or `HOST:PORT`.
- Mint's firewall (`ufw`) is inactive by default. If you enabled it,
  allow outbound: `sudo ufw allow out 4403/tcp`. Check with
  `sudo ufw status verbose`.
- The node must have WiFi enabled and be on the same network/VLAN; client
  isolation on a guest SSID will silently block this.
- Separately, `mesh status` needs outbound HTTPS to loranet.pl and
  lorastats.pl, and will fail at startup with a clear message if
  `MESHPROVISION_CONTACT` is unset. Do not work around a lorastats block
  by retrying -- that site bans IP addresses.

### General

- Add `--log-level debug` (before the subcommand) for a full trace. Key
  material is redacted at every log level.
- `mesh db verify` after any hand-edit; `mesh --version` to confirm which
  build is on `PATH`; `which mesh` if you have more than one venv.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full contribution
workflow (branching, tests-first convention, PR checklist, secret
hygiene). Exact toolchain commands, kept character-identical with
`.github/workflows/ci.yml`:

```bash
pip install -e ".[dev]"
pre-commit install
pre-commit run --all-files
ruff check .
ruff format --check .
mypy --strict src
pytest --cov --cov-report=term-missing
python -m build
```

Run `pre-commit` from the same virtualenv where you ran
`pip install -e ".[dev]"` -- the mypy and no-tracked-secrets hooks are
`language: system` and use the tools already installed there.

Coverage floor is 85% (`[tool.coverage.report] fail_under`); the suite
currently sits well above it. CI runs the 3.11/3.12/3.13 matrix plus a
package-build job.

Bump hook versions with `pre-commit autoupdate` (Dependabot has no
pre-commit ecosystem; it covers `pip` and `github-actions` only).

Regenerate the example database: `python scripts/generate_example_db.py`.

Extend the weak-key blocklist: `python scripts/update_known_bad_keys.py --help`.

## License

MIT. See [`LICENSE`](LICENSE) (also declared in `pyproject.toml`).
