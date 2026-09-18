# The node database (.ods)

Part of the meshprovision docs — see the [README](../README.md).

The database is a real spreadsheet meant to be opened and edited in
LibreOffice, not a CSV dump.

## Nodes sheet

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
| `notes` | TEXT | Free-form operator notes — yours alone. Nothing in meshprovision ever reads or writes this column; it exists purely so you have somewhere in the database itself to record whatever context matters to you (a node's physical location, why it's on a particular firmware, a reminder to revisit its key) |
| `private_key_ref` | DERIVED, formula `=[.A{row}]&"_priv"` | Reference to this node's private key row in the `Keys` sheet |
| `public_key_ref` | DERIVED, formula `=[.A{row}]&"_pub"` | Reference to this node's public key row in the `Keys` sheet |
| `role` | ENUM (dropdown `mp_role`) | Device role, from the installed `Config.DeviceConfig.Role` protobuf enum |
| `region` | ENUM (dropdown `mp_region`) | LoRa region, from the installed `Config.LoRaConfig.RegionCode` protobuf enum |
| `channel_psk_ref` | DERIVED, formula `=[.A{row}]&"_psk"` | Reference to this node's channel PSK row in the `Keys` sheet |
| `ble_pin` | PIN, SECRET | 6-digit `bluetooth.fixed_pin`, stored as text so leading zeros survive; never logged or displayed |
| `management` | ENUM (dropdown `mp_management`) | `template` (the default; `mesh provision` enforces the template on this node) or `observed` (`mesh adopt` recorded this node's live state as-is; `mesh provision` refuses to touch it until `--enroll`). Empty reads back as `template`, so every pre-existing row keeps its current behavior |
| `unregistered_admin_keys` | BASE64_KEY_LIST (`;`-separated), SECRET | Legacy/hand-edit-only column: raw base64-encoded admin public keys (32 bytes each) observed live on this node's `security.adminKey` that couldn't be resolved to any `Keys` sheet ref. `mesh adopt` no longer writes into this column — every admin key it observes now gets a real `Keys` sheet row instead (see [`observed-*` rows](#observed--rows) below) — and drains it on any node it re-adopts. A value here is only ever a leftover from a database written before that change, and not yet re-adopted; `mesh db verify` and `mesh adopt` still check it for the CVE-2025-52464 cross-device duplicate signature it used to be the sole record of. Marked SECRET to match `key_value`'s treatment, even though an admin key is itself a public, not secret, value |
| `archived_at` | TIMESTAMP | UTC timestamp this node was archived (soft-deleted) via `mesh db forget`, or empty if active. Excludes the node from `mesh status` and refuses `mesh provision`/`mesh admin bootstrap`/`mesh adopt`, but every other cell on the row is preserved |

## Keys sheet

| Column | Kind | Notes |
|---|---|---|
| `key_ref` | primary key, DERIVED | `owner_node_id` plus a suffix determined by `key_type` (`_pub`/`_priv`/`_psk`) |
| `owner_node_id` | KEY_REF, required | A node_id hex value, a template `admin_nodes` label, or an `observed-<fingerprint>` synthetic owner `mesh adopt` mints for a key it can't otherwise name (see below) |
| `key_type` | ENUM (dropdown `mp_key_type`) | `admin_public`, `admin_private`, or `channel_psk` |
| `key_value` | BASE64_KEY, required, SECRET | Base64 of exactly 32 raw bytes: an X25519 key for `admin_public`/`admin_private`, or an AES256 channel PSK for `channel_psk`. Never logged or displayed |
| `created_ts` | TIMESTAMP | UTC timestamp this key was recorded |

A `channel_psk` row is only ever written by `mesh adopt --from-backup`
(see [`mesh adopt`](commands.md#mesh-adopt)), decoded from a `.cfg`
profile's `channel_url`, and only when the primary channel's PSK is the
full 32-byte AES256 form — the 0-byte (no encryption), 1-byte ("default"
preset, a firmware-side table index rather than real key material), and
16-byte (AES128) forms cannot round-trip through this column and are
reported as a warning instead. No live-device path writes this row
today: `mesh provision`/`mesh adopt` against a connected device never
read channel configuration at all.

### `observed-*` rows

Every admin key `mesh adopt` observes on a device's `security.adminKey`
gets a `Keys` sheet row, even when nobody has told meshprovision who it
belongs to yet:

- A key that already resolves to a real ref (registered via `mesh admin
  import`/`mesh admin bootstrap`, or belonging to one of the fleet's own
  already-adopted nodes) uses that ref, as before.
- One that doesn't is filed under
  `owner_node_id = observed-<8 hex chars of its own sha256 fingerprint>`
  — content-addressed, so the *same* key observed on several devices
  resolves to one shared row every one of them references. That shared
  `observed-*` ref across two nodes' `authorized_admin_keys` is exactly
  the CVE-2025-52464 cross-device duplicate signature (`mesh db verify`
  reports it CRITICAL).
- `observed-` is a reserved owner prefix — a human-assigned ref can never
  collide with one.

An `observed-*` row is meant to be temporary: as soon as its key's real
owner becomes known — that node itself gets adopted, or an operator runs
`mesh admin import`/`mesh admin bootstrap` for it — every node
authorizing the `observed-*` ref is rewritten to the real one and the
`observed-*` row is deleted. `mesh adopt --show-admin-keys` prints the
`observed-*` ref an unrecognized key was (or will be) filed under,
alongside the `mesh admin import` command that renames it. (An admin key
already on the device but not yet given a human-chosen ref — for example
a trusted friend's, whose private half you never hold or need — is
otherwise reported by fingerprint only, never its raw material;
`--show-admin-keys` is the one deliberate exception, see
[Secret hygiene](security.md#secret-hygiene).)

## How the spreadsheet behaves

- **Formulas for everything derivable**, written with a cached display
  value so the file reads correctly before LibreOffice ever recalculates.
- **Derived columns are never authoritative.** On load, meshprovision
  recomputes each derived value from its sources and uses that, ignoring
  a stale cache. A disagreement logs a warning naming the cell — which
  catches both a stale cache and a hand-edit that broke a formula.
- **Frozen header row** (split at row 1), sensible column widths, a bold
  header, and a long human description attached to each header cell as a
  comment.
- **Dropdowns** (`table:content-validation`) on every fixed-value column.
  LibreOffice treats validation as advisory, so the loader re-validates
  every value anyway and reports the offending sheet/row/column.

## Hand-editing tips

- Format `node_id` as Text (Format > Cells > Text) before typing. This is
  why the project uses `odfpy` directly and not `pandas`: a hex node id
  like `1234567e8` is otherwise parsed as a float in scientific notation,
  silently corrupting the primary key.
- Run `mesh db verify` after every hand-edit. If it fails, see
  **Recovering from a bad hand-edit** below before doing anything else.
- `mesh db backup` before a risky edit; every save also writes a
  timestamped backup into `data/backups/` with a retention limit.
- Opening the database in LibreOffice Calc, resizing columns, and saving
  is safe — including adding your own comments to a cell. Every header
  cell carries its column's description as a built-in Calc comment
  (visible on hover); that comment is documentation only and is ignored
  when the file is read back, along with any comment you add yourself.

### Recovering from a bad hand-edit

Beyond the timestamped backups `mesh db backup`/`--retention` manage,
meshprovision keeps a single **known-good safety copy** — refreshed
automatically every time *any* `mesh` command successfully loads the
database, read or write alike, not just when you remember to run
`mesh db backup` yourself. It always lives at
`data/backups/nodes_db.known-good.ods` (the default backup location,
regardless of any `--backup-dir` a specific `db backup`/`db restore`
invocation used), and it is a best-effort, silent side effect: if it
can't be written (a full disk, a read-only-mounted `data/backups/`), the
command that triggered it still succeeds normally.

If a hand-edit breaks the file badly enough that it no longer loads at
all, the resulting error names the known-good copy's timestamp and the
exact command to undo the damage:

```
error: nodes_db.ods is not a readable ODF spreadsheet: File is not a zip file
Hint: A known-good copy from 2026-09-18T14:02:11Z is available. Run: mesh db restore --known-good
```

```bash
mesh db restore --known-good      # restores it, after the usual confirmation
mesh db verify                    # confirms you're back to a good state
```

`mesh db backup --list` also reports the known-good copy's timestamp
directly, so you can check how fresh it is before relying on it.
Because it is refreshed on every load, it is normally very recent — but
it is still only as good as the last database state some `mesh` command
actually saw, so a hand-edit that both breaks the schema *and* happens
between two edits with no `mesh` command run in between will lose
whatever changed since that last successful load, not just the bad edit
itself.

## The shipped example

`data/nodes_db.example.ods` is a **reference file**, not a starting
point — `mesh init` deliberately creates an empty database rather than
copying it (see [`mesh init`](commands.md#mesh-init)). It ships three
fake nodes:

- `deadbe01` / `MT01` / "Meshtastic MT01" / `HELTEC_V3` — authorizes the
  `example-admin` admin key.
- `deadbe02` / `MT02` / "Meshtastic MT02" / `TRACKER_T1000_E`.
- `deadbe03` / `MT03` / "Meshtastic MT03" / `RAK4631` — deliberately
  provisioned with **zero** admin keys, to show that is a valid outcome.

Keys: `deadbe01_pub`, `deadbe01_psk`, plus an `example-admin_pub` /
`example-admin_priv` pair.

Every key value is a 32-byte ASCII placeholder that spells out what it is
(base64-decode any cell and you get `EXAMPLE-KEY-DO-NOT-USE-000000001`),
so nobody can mistake it for live material — and every placeholder still
passes the weak-key audit with zero findings, which the generator asserts
on each run.

Regenerate it with:

```bash
python scripts/generate_example_db.py
```

All timestamps are pinned to `2026-01-01T12:00:00Z`, so `Nodes`/`Keys`
content is byte-identical across runs; only the zip entries' own mtimes
vary.
