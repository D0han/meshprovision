# Commands

Part of the meshprovision docs — see the [README](../README.md).

The toolkit installs **one** console script, `mesh`, with seven
subcommands/subcommand groups. **Global options go before the
subcommand** — for example `mesh --no-cache status --json`, not
`mesh status --no-cache`. Every command and subcommand supports
`-h`/`--help`.

**Output contract:** STDOUT carries machine-readable output only
(`--json` documents, the `mesh status` table, and `--dry-run` change
lines); logging, prompts, warnings, and errors all go to STDERR — so
`mesh status --json | jq .` never needs filtering.

## Global options

| Option | Meaning |
|---|---|
| `--log-level` | Logging verbosity (default: `MESHPROVISION_LOG_LEVEL`, else `WARNING`) |
| `-v`, `--verbose` | Increase log detail; repeatable. `-v`: this tool's own logs (`INFO`). `-vv`: `DEBUG`, plus `meshtastic`/`httpx`. `-vvv`: also `bleak`/`httpcore`/`urllib3`. An explicit `--log-level` overrides `-v` |
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
turns every prompt into an error — which is what makes `mesh` cron-safe.

## `mesh init`

Creates whatever first-run artifacts (`.env`, `config/template.yaml`,
`data/nodes_db.ods`) are still missing. Prompts for
`MESHPROVISION_CONTACT` — the one value with no default — unless
`--contact` is given. Only ever creates what is missing, so it is safe to
re-run. The database is created empty via the same schema-writer `mesh db
restore` uses, **never** copied from `data/nodes_db.example.ods`, which
carries fake illustrative rows.

Any `mesh` command run interactively offers this same wizard whenever
setup is incomplete, before the command it was actually asked to run gets
a chance to fail with a "file not found" error. That offer never fires
for a help-only invocation, for `mesh init` itself, or when
`--non-interactive`/a non-TTY stdin applies — a non-interactive run with
missing setup keeps failing exactly as it always has, with the same hint.

```bash
mesh init                                      # prompts for everything missing
mesh init --yes --contact ops@example.org      # fully scriptable
mesh init --json                               # machine-readable summary
```

| Option | Meaning |
|---|---|
| `-y`, `--yes` | Create every missing file without asking |
| `--contact` | Value for `MESHPROVISION_CONTACT`; skips the prompt |
| `--json` | Emit JSON instead of human text |

## `mesh provision`

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
`mesh adopt`, below — or simply a row you typed in by hand, since a blank
`management` cell reads back as `observed`) is refused with exit code 5
unless `--enroll` is passed — checked before any admin-key resolution
runs, and before
`--dry-run`'s early return, so an unenrolled node never even reaches a
plan preview it didn't ask for. `mesh admin bootstrap` inherits the same
gate, since it drives this same pipeline. `--enroll` graduates the row to
`management=template` on a successful apply; it is a one-time flag —
once enrolled, ordinary `mesh provision` runs need it again.

A node archived via `mesh db forget` is refused outright, checked before
the enrollment gate (exit code 5, no bypass flag) — `mesh admin
bootstrap` inherits this too.

**Transactional guarantee:** after each `writeConfig(section)` the config
is re-read and compared to intent; key writes are additionally verified
by reading the public key back off the device. Any unconfirmed write
marks the node `UNCERTAIN`, leaves the ODS **unchanged**, logs a warning,
and exits non-zero.

**Concurrent-write guarantee:** writers (`mesh provision`, `mesh admin
bootstrap`/`import`) hold an exclusive lock on `<db>.lock` for the whole
load-modify-save cycle, including the device conversation and any
confirmation prompt. `mesh db backup` takes no lock — it copies the raw
file with `shutil.copy2`, which follows the inode it opened through to
completion even if a concurrent writer replaces the path mid-copy, so a
backup is always a complete snapshot of one version of the database. A
second write command that can't acquire the lock within
`MESHPROVISION_LOCK_TIMEOUT` seconds (default 60, sized for a full
multi-section device transaction) fails fast with exit code 4 and a
message naming the holder's pid when known, rather than silently
discarding whichever write loses the race. Read-only commands (`mesh
status`, `mesh db verify`, `mesh db backup`) are never blocked by it.
`--dry-run` doesn't take the lock. POSIX only: on a platform without
`fcntl` the lock is a no-op, logged once at WARNING.

## `mesh adopt`

For a node that is already configured and already in service — the
normal case for an existing fleet you're bringing into meshprovision for
the first time. Connects the same way `mesh provision` does, but is
**strictly read-only toward the device**: it never calls `writeConfig`,
never diffs against the template, and never renames, reconfigures, or
regenerates anything on the node. It records the device's actual live
state — names, admin keys, firmware version, region, role, BLE PIN —
into the database as `management=observed`, so `mesh provision` leaves
it alone until you explicitly decide otherwise with `--enroll`.

```bash
mesh adopt --port /dev/ttyUSB0
mesh adopt --dry-run --interface tcp --host 192.168.1.50
mesh adopt --port /dev/ttyUSB0 --yes --show-admin-keys
mesh adopt --port /dev/ttyUSB0 --force
mesh adopt --from-backup Meshtastic_MT01.cfg --node-id !a0cb5cc4
mesh adopt --from-backup profile.cfg --from-backup nodedb.json --yes
```

| Option | Meaning |
|---|---|
| `--from-backup PATH` | Adopt from an exported Meshtastic app config backup instead of a device — repeatable, see below |
| `--node-id ID` | Authoritative node id for `--from-backup` (any form `mesh` accepts: `!a0cb5cc4`, `a0cb5cc4`, or decimal) |
| `--no-lookup` | With `--from-backup`, skip the loranet long-name lookup used to suggest `--node-id` |
| `--no-channel-psk` | With `--from-backup`, don't record the channel PSK decoded from `channel_url` |
| `--dry-run` | Print the report without writing to the database |
| `-y`, `--yes` | Assume yes to every confirmation |
| `--json` | Emit JSON instead of human text |
| `--force` | Re-adopt (demote) a node that is currently `management=template`; with `--from-backup`, also proceeds despite conflicting node-id evidence (see below) |
| `--show-admin-keys` | Print the `mesh admin import` command (and the raw base64) for each admin key the device reports that isn't already registered under a real ref |

`mesh adopt` also records the node's own keypair — its public half
always, and its private half too when the device exposes one — the same
`<node_id>_pub`/`<node_id>_priv` shape `mesh provision` writes, so
`public_key_ref`/`private_key_ref` on the Nodes row actually resolve.

Every admin key the device reports gets registered under a real or
synthetic `Keys` sheet ref — see
[`observed-*` rows](database.md#observed--rows) for how that resolution
works and how `--show-admin-keys`/`mesh admin import` turns a synthetic
ref into a named one.

Re-adopting an already-`observed` node **replaces** `authorized_admin_keys`
with exactly what's currently live — unlike `mesh provision`'s
narrow-only rule for a template-managed row, an observed row has no
desired state to preserve against, so it mirrors reality every time,
including dropping a ref for a key that's no longer on the device.
Re-adopting a `management=template` row is refused unless `--force` is
passed, and the confirmation prompt names the demotion explicitly. A
node archived via `mesh db forget` is refused outright, `--force`
included — archiving is a separate, deliberate decommission decision
that `mesh adopt` never silently reverses.

**Typical workflow for an existing fleet:**

```bash
mesh adopt --port /dev/ttyUSB0                    # record what's actually there
mesh admin import FRIEND=<base64-from-the-report>  # only if it reports an unregistered key you want to keep
mesh provision --port /dev/ttyUSB0 --enroll        # only when you're ready for template enforcement
```

The last step is optional and per-node — a fleet can stay `observed`
indefinitely; `mesh status` and `mesh db verify` work the same either way.

**Adopting from a config backup, for a node you can't currently reach:**
`--from-backup` builds the exact same report and does the exact same
writes as a live-device adopt, from a Meshtastic app export instead of a
device — no interface is ever opened. Pass one or two files (repeat the
flag), auto-detected by content:

- A **`.cfg` profile** — Radio Config → Backup & Restore → Export in the
  app. Carries names, `channel_url`, full config (including the node's
  own public/private key and any admin keys), the BLE PIN, and an
  optional fixed position. Carries no node id, hardware model, or
  firmware version.
- A **node-db JSON export** — Settings → Export node database in the
  app (`Meshtastic_nodedb_<SHORT>_<ts>.json`). Carries `myNodeNum` and,
  for the exporting node's own entry, its id, hardware model, role, and
  firmware version. Carries no private key, admin keys, region, or
  channel — the two files are complementary.
- A **YAML profile** — `meshtastic --export-config`'s output (the Python
  CLI, not the app). Same content as a `.cfg`.

A backup never asserts its own node id with authority — even a node-db
export's `myNodeNum` is a self-reported value a hand-edited or
mismatched file could get wrong — so `mesh adopt` resolves one from,
in order of strength: an explicit `--node-id`; a `Keys` sheet public-key
match (the backup's own public key already belongs to a registered
`<id>_pub` row); or a paired node-db export's `myNodeNum`. Two of these
disagreeing is a refusal unless `--force` is passed (which then falls
back to the same precedence order). If none of them resolve anything,
and `--no-lookup` wasn't passed, `mesh adopt` searches loranet's dump for
a `long_name` match and prints it as a `--node-id` hint — **this is
advisory only**; a name match is never enough on its own to adopt a
node, since names collide and a `.cfg`'s `long_name` is exactly the kind
of thing an attacker crafting a lookalike backup could set. See
[Firmware 2.8 and beyond](firmware-compatibility.md) for the broader
node-identity-trust concern this mirrors.

A `.cfg`'s `channel_url` is decoded and, when the primary channel's PSK
is the full 32-byte AES256 form, recorded as a `<node_id>_psk` row (the
one case this project's `Keys` sheet can hold — see
[Keys sheet](database.md#keys-sheet)); a 1-byte "default preset" or
16-byte AES128 PSK is reported as a warning and never written.
`--no-channel-psk` skips this entirely. A `.cfg`'s `fixed_position`, when
set, fills `gps_lat`/`gps_lon`/`gps_alt`. Both, like `hw_model` and
`firmware_version`, are only ever *added* on re-adopt — a `--from-backup`
run that doesn't report one never blanks a value a previous adopt
recorded.

Because a `.cfg`/YAML profile is the one place `mesh adopt` ever sees a
node's *private* key without touching the device, it also runs the
weak-key audit against the node's own keypair (consistency included) —
the live-device path has never done this, since `build_adoption_report`
only audits admin keys.

## `mesh status`

Strictly read-only — it never writes to the database or to any device.
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

Short/Long prefer the most recently observed name; a node no source has seen
this run still shows the name already on file in the `Nodes` sheet, so it
stays identifiable instead of rendering `-`.

**Timestamps.** The table's `Timestamp` column and the summary caption's
`data as of` clause (below) render in the machine's local timezone (the
standard `TZ` environment variable overrides it, same as any other
timezone-aware program); `--json` stays UTC (`Z`-suffixed) throughout, so
scripted consumers get byte-identical output regardless of the host's
timezone or DST. Since every row is in that same one zone, it's named once
in the column header (`Timestamp (CEST)`) rather than repeated per row.

The summary caption also states how stale the report is, per source, since
a status run can be served entirely from the HTTP cache: `data as of
loranet 14:28:03, lorastats 14:32:10 CEST` is when that source's data was
actually last fetched from the network — not "now" — so a cache hit never
masquerades as fresh data. `--json` carries the same information, in UTC,
under `data_as_of`.

`--watch` respects the cache TTL (default poll interval = the cache TTL,
floored at 5 s) and prints a per-poll cache hit/miss/request line to
stderr.

`--fail-on-offline` is **on by default**: an offline node, or any source
failure, exits `7`. Pass `--no-fail-on-offline` to suppress that.

**Cache note:** every outbound request goes through the TTL disk cache; a
second run inside the TTL performs zero network calls. `--no-cache` /
`--force-refresh` bypasses reads but still writes the response back.

**Archived nodes** (see `mesh db forget` below) are excluded from the
default report — an explicit `--node` request for one still wins.

## `mesh admin`

No node can be provisioned as managed until some admin's public key
already exists in the `Keys` sheet — that chicken-and-egg problem has two
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
  those devices are next connected — the run **reports** which
  cross-authorizations are still pending rather than silently skipping
  them. It reuses `run_provision` wholesale, so it accepts and honors
  every option in `mesh provision`'s table above (`--dry-run`, `--enroll`,
  `--allow-lockdown`, `--allow-weak-admin-key`, `--force-regenerate-key`,
  `--no-reconnect`, `-y`/`--yes`, `--json`) in addition to its own `--ref`.
- `import` registers a public key you already hold, without touching a
  device. It validates length and canonical base64, runs the weak-key
  audit, and refuses a key already registered under a different reference
  unless `--force` — except when that other reference is one of `mesh
  adopt`'s own `observed-*` refs, which is not a collision to refuse but
  exactly the rename this command performs (see
  [`observed-*` rows](database.md#observed--rows)). `--dry-run` runs every
  one of those checks and reports the outcome (including a refusal)
  without registering anything, matching `provision`/`adopt`/`admin
  bootstrap`'s existing `--dry-run` convention.
- `list` shows each admin's ref, whether the public key is present, a
  redacted fingerprint, whether the private counterpart is on hand,
  whether it is in the template, which node it resolves to, its weak-key
  audit result (`-` when no key is present, else `clean`, `warning`, or
  `compromised`), which nodes authorize it, and which authorizations are
  pending. Exits `2` if a
  template-listed admin is missing from the `Keys` sheet.

A REF is a label, never a key, and must not end in `_pub`/`_priv`/`_psk`
or start with `observed-` (reserved for `mesh adopt`'s own synthetic
refs).

## `mesh db`

```bash
mesh db verify
mesh db verify --strict
mesh db verify --json
mesh db backup
mesh db backup --list
mesh db backup --retention 20 --backup-dir /mnt/usb/mesh-backups
mesh db restore data/backups/nodes_db-20260101T000000.000000Z.ods
mesh db restore --known-good
mesh db list
mesh db list --json
mesh db forget deadbe01
```

| Option | Meaning |
|---|---|
| `--strict` (`verify`) | Treat a bare warning (no error or critical problem) as a failing exit code too |
| `--backup-dir` (`backup`, `restore`) | Directory backups are stored under/read from. Defaults to `data/backups`. Never affects where the known-good copy lives (see below) — that's always the default location |
| `--retention` (`backup`) | Number of backups to retain (default: 20) |
| `--list` (`backup`) | List existing backups instead of creating one; also reports the known-good copy's timestamp, when one exists |
| `--known-good` (`restore`) | Restore the known-good safety copy instead of naming a `BACKUP` path — mutually exclusive with it |
| `-y`/`--yes` (`restore`, `forget`) | Assume yes to the confirmation |
| `--json` | Emit JSON instead of human text |

- `verify` layers cross-reference checks, a weak-key audit over every key
  row, and alias-aware cross-fleet duplicate detection on top of the
  schema validation that already happens at load. Because `mesh admin
  bootstrap --ref LABEL` deliberately files one physical node's key under
  both `<node_id>_pub` and `<LABEL>_pub`, a duplicate group is
  **critical** only when it spans two or more **distinct real nodes** —
  the CVE-2025-52464 vendor key-cloning signature. A node-plus-label
  group is an informational alias warning.
- `backup` writes only into the backup directory and never rewrites the
  database itself.
- `restore` is the only `db` subcommand that rewrites the live database
  directly, so unlike `backup` it holds the cross-process write lock for
  the whole operation, excluding a concurrent `mesh provision`/`mesh
  admin` run. The current database is itself backed up first, so a
  restore is always reversible via `mesh db backup --list`. The restored
  file is loaded back immediately to confirm it is actually valid —
  restoring a corrupt or non-ODS file fails loudly on the spot rather
  than breaking the next unrelated `mesh` command. Pass either a
  `BACKUP` path or `--known-good`, never both — the latter restores the
  single safety copy every successful database load refreshes (see
  [Recovering from a bad hand-edit](database.md#recovering-from-a-bad-hand-edit)),
  which is also exactly what a load-failure error's hint points at.
- `list` is the offline counterpart to `mesh status`: a plain dump of the
  `Nodes` sheet's own content (short/long name, hardware model, firmware,
  management mode, region, role, authorized admin key refs, notes) —
  no device connection, no `MESHPROVISION_CONTACT`, no network round
  trip. Shows an `Archived` column/field for every node, archived or not.
- `forget` archives (soft-deletes) a node: it's excluded from `mesh
  status`'s default report and refused by `mesh provision`/`mesh admin
  bootstrap`/`mesh adopt` (not bypassable with `--force`), but its row —
  including `authorized_admin_keys` and `notes` — is never deleted, so
  audit history survives. `mesh db list` still shows it by default. Its
  `short_name`/`long_name` are freed for a replacement device to reuse
  (an archived node's name is excluded from the pattern's used-name
  count, unlike every other field on the row). There is currently no
  CLI command to un-archive a node; the hint on a refused command names
  the manual workaround (edit the `archived_at` cell by hand).

## `mesh template`

```bash
mesh template validate
mesh --template-path ./candidate.yaml template validate --json
```

`validate` checks the configured template file — name pattern byte
limits, namespace capacity, `admin_nodes` shape and count, forbidden
key-material fields — with no database and no device connection at all.
`mesh db verify` already runs the same checks as part of validating a
database, but deliberately *degrades* a template failure to a warning
there (verifying a database has to keep working even with a broken
template); `mesh template validate` is the fast, standalone way to check
"is my template valid" on its own, and lets a template failure be the
command's own real, non-degraded result. Uses whichever template path
`--template-path`/`MESHPROVISION_TEMPLATE_PATH`/`.env` resolves to —
there is no separate override specific to this command.

## Exit codes

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

Exit code 4 (`DB`) also covers "another mesh command is running": a
write command that could not acquire the database's write lock within
`MESHPROVISION_LOCK_TIMEOUT` raises `DatabaseLockedError`, distinct from
the pre-existing `AtomicWriteError` raised on a filesystem failure
(read-only filesystem, missing parent) while creating the lock file
itself — both share exit code 4, since the message text is the intended
disambiguation channel between them, not the exit code.

Exit code 5 (`PROVISIONING`) also covers two `mesh adopt`/`--enroll`
refusals: `NodeNotEnrolledError` (a `management=observed` node touched by
`mesh provision` without `--enroll`) and `AdoptionRefusedError` (a
`management=template` node re-adopted without `--force`) — again
disambiguated by message text, not exit code. `mesh adopt --from-backup`
adds `NodeIdentityError` to this same code: its node id could not be
resolved at all, or resolved ambiguously without `--force` (see
[Adopting from a config backup](#mesh-adopt) above).

Exit code 2 (`CONFIG`) also covers `mesh adopt --from-backup`'s
`BackupParseError`: an unreadable path, a file matching none of the
three supported backup shapes, a structurally invalid one, or two
backup files that disagree about which node they describe.
