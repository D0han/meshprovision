# Commands

Part of the meshprovision docs — see the [README](../README.md).

The toolkit installs **one** console script, `mesh`, with nine
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
| `--env-file` | Explicit `.env` file to read instead of searching upward from the CWD. Must exist (except for `mesh init`, which creates it); a missing file is an error rather than a silent fall-back to the defaults |
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

A node with no recorded key that reports a valid keypair has that
keypair recorded (`origin=captured`), not regenerated; a key already
registered under another ref is refused, unless that ref is the one
being bootstrapped with `mesh admin bootstrap --ref`.

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
| `--allow-weak-admin-key` | Authorize admin keys that fail the weak-key audit; does not relax the `security.is_managed` safety gate, and never overrides an all-zero or small-order key |
| `--force-regenerate-key` | Regenerate the node keypair unconditionally |
| `--rename` | Allow renaming an already-provisioned node |
| `--no-reconnect` | Verify writes against the in-memory interface only (weaker guarantee) |
| `--json` | Emit JSON instead of human text |

`--no-reconnect` is a deliberately **weaker** guarantee: writes are
verified against the in-memory interface only. The default reconnects and
re-reads, because of firmware issue #7449 (a restored private key could
be discarded on reboot, with the device regenerating fresh keys).

Because `--no-reconnect` never reconnects, it has no way to tell a key
that genuinely persisted apart from one firmware silently discarded on
reboot, so it refuses outright -- before any device I/O -- whenever the
plan would regenerate the node's key. A FACTORY node always regenerates a
key, so a FACTORY node can never be provisioned with `--no-reconnect`. For
everything else (renames, ordinary field writes), a write that can't be
read back is reported `CONFIRMED` with a `"written; not read back
(--no-reconnect)"` note rather than being misreported as a mismatch.

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

A node whose recorded key also backs an authorized admin key is refused
(exit code 5, `AdminKeyRotationRefusedError`, no bypass flag —
`--force-regenerate-key`, `--allow-weak-admin-key`, `--allow-lockdown`,
`--enroll` and `--rename` all still refuse) the moment the plan would
regenerate or adopt a new keypair for it. `mesh admin bootstrap` inherits
this too. Nothing is written to the device or the database. See
["Rotating an admin node's key"](security.md#rotating-an-admin-nodes-key)
for the out-of-band procedure a genuine rotation requires.

**Transactional guarantee:** after each `writeConfig(section)` the config
is re-read and compared to intent; key writes are additionally verified
by reading the public key back off the device. Any unconfirmed write
marks the node `UNCERTAIN`, leaves the ODS **unchanged**, logs a warning,
and exits non-zero. A run that stops early lists every section it never
sent as "Not written". If committing the settings transaction fails,
each section already sent is reported `unconfirmed` (the device may or
may not have saved it) and is not re-read. Whenever a `security`
section that sets `is_managed` was sent but never confirmed, the run
warns that the node may now be locked to its admin keys.

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
The private half is only recorded when it is proven to derive the
reported public key. When it is not (a node-db `.json` backup, or a
device that does not expose a matching private key) and an existing
`<node_id>_priv` row does not belong to the public key being recorded,
`mesh adopt` refuses, `--dry-run` and `--force` included, rather than
leave a mismatched pair. It never deletes that row for you: back up the
database (`mesh db backup`), remove the row from the `Keys` sheet by
hand if the old key is really no longer needed, and re-run, or adopt
from a source that reports the matching private key.

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
A blank short or long name (a device whose NodeDB is not yet repopulated
after a reboot, or a backup without an owner) is no evidence and keeps the
recorded name, and a BLE PIN already recorded is kept when the device has
no fixed PIN (`mesh provision --enroll` then sets that recorded PIN).
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
back to the same precedence order). When `--force` overrides a paired
node-db export's `myNodeNum`, that export's entry is ignored; if the
paired profile carries the same public key as that entry, both files
describe the export's node, and `mesh adopt` refuses even with `--force`
rather than file that node's key under another id. If none of them resolve anything,
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
set with a non-zero latitude or longitude, fills `gps_lat`/`gps_lon`/`gps_alt`
(latitude and longitude both 0 is no position, as in a YAML backup). Both,
like `hw_model` and `firmware_version`, are only ever *added* on re-adopt — a
`--from-backup` run that doesn't report one never blanks a value a previous
adopt recorded.

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
corroboration); most recent wins. Whether a node is online, stale or offline
depends on how often it is expected to be heard (see **Online, stale,
offline** below): a client with default settings is stale after 6 h 45 m and
offline after 24 h; nothing is ever stale before 2 h or offline before 24 h.

**Online, stale, offline.** A node is judged against its *expected interval*
`E`, the longest gap a healthy node of its configuration leaves between two
packets, taken from the first of:

| Source (`--json` `expected_interval_source`) | `E` |
|---|---|
| `override` | `--expected-interval HOURS` (every reported node; combine with `--node`) |
| `history` | the mean gap between the hours its [`mesh health`](#mesh-health) history heard it in (last 7 days; needs 3 heard hours; hours after the last heard one do not count, so an outage does not stretch its own interval) |
| `template` | for a template-managed node: the template's `device.node_info_broadcast_secs` (raised to the firmware's minimum of 1 h; unset means the role default of the template's `device.role`) |
| `role` | its role's node-info default: 3 h; 24 h for `TAK`/`TAK_TRACKER`; 48 h for `CLIENT_HIDDEN`/`REPEATER`, which send none |

`E` is at most 48 h. Then

- stale after `max(2 h, 2 E + E/4)`: two expected packets missed (the firmware
  itself forgets a neighbour after twice its interval), plus a quarter
  interval for send jitter and upload delays;
- offline after `max(24 h, 5 E + E/4)`: five in a row missed, which happens
  well under once a month for a 6-hourly node even at 30% packet loss
  (broadcasts are never retried).

| `E` | stale after | offline after |
|---|---|---|
| 1 h | 2 h 15 m | 24 h |
| 3 h (role default) | 6 h 45 m | 24 h |
| 6 h | 13 h 30 m | 31 h 30 m |
| 12 h | 27 h | 63 h |
| 24 h (TAK) | 54 h | 126 h |

Node info anchors the defaults because every role but `CLIENT_HIDDEN` sends
it, and unlike telemetry and position the firmware never stretches its
interval on a crowded mesh (above 40 nodes online it multiplies those by up to
14 on `LONG_FAST`), nor holds it back below 40% channel utilization; device
telemetry is also off by default in recent firmware. `--stale-after` and
`--offline-after` (default 2 and 24 hours) are the floors, so
`--expected-interval 0.5` gives the fixed 2 h / 24 h thresholds of earlier
versions. The template is the one `MESHPROVISION_TEMPLATE_PATH` names: a
missing file is skipped silently, one that does not load with one warning, and
it is not read at all with `--expected-interval`. `--json` gives each
node's `expected_interval_seconds`, `expected_interval_source`,
`stale_after_seconds` and `offline_after_seconds`; the top-level `thresholds`
are the floors. Learning reads the history files only (no request); a node
gets a history from `mesh health` or `mesh status --detail full`.

`--region` (repeatable) names the lorastats region(s) to query, in order. It
overrides `MESHPROVISION_LORASTATS_REGIONS` (comma-separated). Regions are
matched exactly as typed, after Unicode NFC normalization (so `Zachód` typed
with a combining accent is the same region, and a region given twice is
queried once); `Zachód` and `zachód` are different regions to this tool. At
most 16 regions can be given.

**Region list.** When neither is given, `mesh status` asks the regions
lorastats.pl publishes in its own site navigation (`Warszawa`, `Zachód`,
`Gdańsk`, ... at the time of writing; they can change). lorastats.pl has no
API that lists them, so mesh reads the region links of one server-rendered
page, `https://lorastats.pl/Nodes`, although lorastats.pl asks API clients
not to scrape its HTML pages and bans IP addresses that do. To keep that to
one request a week:

- the page is requested only when no region is configured;
- the list is kept in `lorastats_region_list.json` in the cache directory for
  7 days; `--no-cache`, `--force-refresh` and `--watch` polls never request
  it again, only `mesh status --refresh-regions` does (refused when regions
  are configured), and at most once per `mesh` process;
- only the link targets are read: no script runs, no link is followed,
  nothing of the page is logged, and every name must pass the same check as
  `--region`.

If the page cannot be read (or names no region) the cached list is used, with
a warning, however old; without one, lorastats is reported as a failed source
whose hint asks you to set `MESHPROVISION_LORASTATS_REGIONS`. There is no
built-in list. To never request the page, configure the regions, for example
`MESHPROVISION_LORASTATS_REGIONS=Zachód,Warszawa`.

**Which region a node is in.** lorastats.pl only answers for a node in the
region it lives in (by its last reported position); any other region answers
like "no data". With more than one region, `mesh status` learns where each
node lives:

- the region a node was last found in is remembered in
  `lorastats_regions.json` in the cache directory (for 30 days) and asked
  first, alone, while it keeps answering; a remembered region that is no
  longer in the list is ignored;
- otherwise lorastats.pl's region-free status endpoint is asked first: a node
  it does not know (HTTP 404) is not asked about in any region, and not asked
  about again for an hour; for a known one the regions are asked in order
  until one answers.

So each node costs one request when its remembered region answers, one when
lorastats does not know it, and at most one more than the number of regions
otherwise (with lorastats.pl's 10 regions: 11, at most 17 with 16 regions).
Reading the region list adds one request a week. A single region is asked
directly, one request per node. A status answer other than 200, 404 or 500
makes lorastats a failed source for that run. `--json` names the region a
node was found in as `lorastats_region` (`null` when lorastats did not report
the node).

```bash
mesh status
mesh status --json
mesh status --node deadbe01 --node '!a0cb5cc4'
mesh status --source loranet
mesh status --region Zachód --region Gdańsk
mesh status --refresh-regions
mesh status --stale-after 1 --offline-after 12
mesh status --node deadbe01 --expected-interval 6
mesh status --watch --interval 60
mesh --no-cache status --json
mesh status --no-fail-on-offline
mesh status --detail brief
mesh status --detail full
```

The rendered table columns are: Node, Short, Long, Mgmt, Status, Last seen,
Every, Timestamp, Metrics, Batt, Volt, ChUtil, AirTx, Seen By, Uptime.

**`--detail`** chooses the table's columns; `--json` is the same for `brief`
and `default`.

- `default`: the columns above, exactly as without `--detail`.
- `brief`: Node, Short, Status, Last seen, Batt, Seen By, Uptime -- the least
  that tells, at a glance, which node it is, whether and when it was last
  heard, whether its battery holds, whether gateways still relay it and
  whether it rebooted recently.
- `full`: the default columns plus the health of [`mesh health`](#mesh-health)
  over 7 days for every reported node: Health (the verdict), Pkt/h, GWs,
  Direct, Hops max/limit, SNR median, Top relay, and a caption line on the
  refresh. It refreshes each node's history exactly as `mesh health` does
  (two lorastats requests per node with a known region, at most once every 10
  minutes, never a gateway check; `--watch` polls share that interval), so it
  costs up to `2 N` requests more than `default`, and none within 10 minutes
  of the previous refresh. `--json` keeps every key and adds `health` per
  node (as in `mesh health --json`) and a top-level `health` (`days`,
  `network_requests`, `refresh`, `failures`). The exit code is decided as
  without `--detail`: health verdicts and refresh failures do not change it
  (use `mesh health` for that).

`mesh status` without `--detail full` never asks for packet reports.

- **Every** is the node's expected interval `E` (see above), gray when it is
  only its role's default.
- **Metrics** is how long ago the device last reported its metrics (loranet's
  `lastDeviceMetrics`); `Batt`, `Volt`, `ChUtil` and `AirTx` are as of that
  moment, which can be much older than `Last seen` (a node that is still
  relayed by gateways keeps a fresh `Last seen`). A battery level of 0% or
  less is shown as `-`: it is no reading (a node without a battery sensor
  reports 0).
- **Seen By** is `1d/7d/30d`: how many distinct MQTT gateway topics relayed the
  node within the last day, week and month (loranet's `seenBy`). It is not a
  radio-neighbour count. `--json` keeps `neighbor_count` (all time) and adds
  `seen_by_counts` (`day`/`week`/`month`), `last_device_metrics` and
  `last_boot`.
- **Uptime** is the time since the last boot: `now - LastBoot` from lorastats
  for an online node. For a stale, offline or unknown node it is the uptime
  as of `Last seen` (`Last seen - LastBoot`, drawn gray), since the node may
  have gone down after that. It is `-` when no source reports a boot time,
  and also when the device's own metrics show a reboot after that `LastBoot`
  (the uptime they report is more than 65 minutes shorter than the time from
  `LastBoot` to those metrics). The uptime a device sends with its metrics is
  not used as a fallback, since it is as old as those metrics.

Colors mark individual cells, not whole rows. `Status` is green / yellow / red
for online / stale / offline. `Last seen`, `Timestamp`, `Metrics` and the four
readings fade green (within 24 h), yellow (2 days), orange (7 days) and red
(older), each tier stretched to the node's own thresholds: green at least
until the node is stale, yellow and orange at least until it is offline (so
the colors only differ from the fixed tiers for a node expected less often
than about every 9 h 36 m); gray means the timestamp is unknown. A reading that is itself
suspicious is drawn bold orange, and an alarming one bold red, whatever its
age: battery at or below 20% / 10%, voltage at or below 3.5 V / 3.3 V,
channel utilization above 25% / 40%, transmit air utilization above 5% / 10%.
`Seen By` is orange when no gateway relayed the node for a week and red when
none did for a month; `Uptime` is orange under an hour (a recent reboot) and
gray for a node that is not online.
These thresholds are heuristics, not firmware limits.

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
floored at 5 s, capped at one week) and
prints a per-poll cache hit/miss/request line to stderr. With `--no-cache`,
only the first successful poll bypasses the cache; later polls respect the
TTL like a plain `--watch` (lower `--cache-ttl` for fresher data), so a
short `--interval` never re-queries lorastats for every node on every poll. `--interval`
takes 1 s up to one week, `--stale-after`/`--offline-after` up to
1000000 hours and `--expected-interval` up to 48 hours (all above 0); a value
outside that range, `nan` or `inf` is a usage error (exit code `2`).

`--fail-on-offline` is **on by default**: an offline node, or any source
failure, exits `7`. Pass `--no-fail-on-offline` to suppress that.

**Cache note:** every outbound request goes through the TTL disk cache; a
second run inside the TTL performs zero network calls. A response that is
rejected as invalid (a maintenance or error page served with HTTP 200, an
empty or unrecognised loranet dump) is dropped from the cache, so the next
run fetches it again instead of failing until the TTL expires. `--no-cache` /
`--force-refresh` bypasses reads but still writes the response back.
Otherwise, lorastats responses are reused for at least 60 s (status-endpoint
answers for at least an hour), even with `--cache-ttl 0`, so a short `--watch
--interval` cannot query lorastats about every node on every poll. The
remembered regions are used with `--no-cache` too. A host that answers HTTP 429 (rate limited) is not
asked again by the same `mesh` process for the `Retry-After` time it gave (10
minutes when it gave none, at most a day); meanwhile each `--watch` poll lists
that source as failed and says when it will retry.

**Archived nodes** (see `mesh db forget` below) are excluded from the
default report — an explicit `--node` request for one still wins.

## `mesh health`

Per-node health and importance from lorastats.pl's packet reports, with a
local 30-day history. Read-only like `mesh status`: it never writes to the
database or to any device; besides what `mesh status` writes it keeps one
history file per node in the cache directory.

```bash
mesh health                     # every active node, one row each
mesh health ab446357            # one node in detail (several can be given)
mesh health --days 30 --json
mesh health --no-fetch          # history and database only, no request at all
mesh health --refresh           # refresh even if refreshed in the last 10 minutes
```

| Option | Meaning |
|---|---|
| `NODE` (any number) | Report on these nodes in detail instead of every active node in a table; also checks what each uplinked as an MQTT gateway |
| `--days N` | Window of the history to judge, 1 to 30 days (default 7) |
| `--no-fetch` | Ask nothing: use the local history and the database only (no `MESHPROVISION_CONTACT` needed) |
| `--refresh` | Refresh the history even if it was refreshed in the last 10 minutes (still at most once a minute per node); refused with `--no-fetch` |
| `--expected-interval HOURS` | Every reported node's expected interval (above 0, at most 48), as for `mesh status`; without it each node's is learned from its history, else taken from the template or its role |
| `--json` | Emit one JSON document instead of text |

The regions are those of `mesh status` (`MESHPROVISION_LORASTATS_REGIONS`, else
lorastats.pl's region list); global `--no-cache` applies to the `mesh status`
part. Exit code `7` when any node's verdict is `crit` or any source or refresh
failed, else `0`.

**What it asks, and how often.** `mesh health` first runs the collection of
`mesh status` for the reported nodes (same requests, same caching, see above).
Then, for every reported node that lorastats reported in a region (a node whose
region is not known is never looked for and shows "without lorastats data"),
it refreshes the node's history with two requests:
`/API/{region}/PacketReports/JSON?fromNode=<id>&since=<time>` and
`/API/{region}/PacketsParsed/JSON?fromNode=<id>&since=<time>`. With `NODE`
arguments it adds `/API/{region}/PacketReports/JSON?gateway=<id>&since=<1 h
ago>` for each, at most once an hour per node. A node's history is refreshed
at most once every 10 minutes (once a minute with `--refresh`), counted from
the refresh stored in its history file and, within one process, from the last
attempt even if it failed or could not be stored. So, beyond `mesh status`:

| Case | lorastats requests |
|---|---|
| a node refreshed in the last 10 minutes (1 minute with `--refresh`) | 0 |
| a node without a known lorastats region | 0 |
| a due node | 2 |
| a due node with `mesh health NODE` | 3 (the gateway check at most once an hour) |
| `--no-fetch` | 0 (and no other request either) |
| worst case, `N` due nodes | `2 N`, `3 N` with `NODE` arguments |

plus the HTTP client's usual retries of a request that failed with a 5xx or
transport error. The answers are fetched fresh, at most 8 MiB each, and not
kept in the HTTP cache (each `since` is a different URL); after a 429 answer
no further lorastats request is sent for the cool-down `mesh status`
documents, and each remaining node is reported as failed.

**The history.** lorastats keeps its reports for only a day or two, so each
node's history is kept in `health/<node id>.json` in the cache directory, for
30 days: per UTC hour the receptions, packets, direct receptions, receptions
per gateway and per relay byte (the busiest 64 of each), per hop count and per
whole-dB SNR step, an RSSI sum/min/max and the decoded packets per port and
per `HopStart`; plus the telemetry readings, local-stats counters, positions,
the newest node info, neighbours, boot times (lorastats' `LastBoot` as `mesh
status` saw it) and gateway checks. A refresh asks from one hour before the
start of the hour of the previous one (the extra hour absorbs a Warsaw-time
`since` misread around a DST change) and *replaces* those hours rather than
adding to them, so running it twice, or two `mesh` processes running it at
once, never counts a packet twice. An hour that lorastats was asked about and
heard nothing in is recorded as silent; an hour nobody asked about stays
unknown (a node's first refresh records silent hours only from its oldest
reception on). Everything older than 30 days is dropped on every write, a file
is at most 2 MiB (the oldest days go first), at most 128 node files are kept
(the least recently written go first), and a file not written for 30 days is
deleted: at most 256 MiB in all; a month of a node heard by 10-30 gateways an
hour takes 0.5-1 MB. Files are written atomically and owner-only; a missing,
corrupt or foreign file reads as an empty history. Deleting the directory only
loses the history.

**The table** (no `NODE`): Node, Short, Verdict, Importance, Last heard (the
newer of the last reception in the history and `mesh status`'s last seen),
Every (the node's expected interval, see [`mesh status`](#mesh-status)), Pkt/h, GWs (distinct gateways in the window), Direct (share of direct
receptions), Hops max/limit (most hops seen / the node's `HopStart`; `?` when
unknown), SNR median, Top relay (busiest relay byte and its share), Batt, and
the first two reasons. **The detailed report** (`NODE`) shows the expected interval, where it came
from and the stale and offline thresholds it gives, every metric with its
sample size, the gateways, hop counts, relays (with the node of ours each
byte likely is), decoded packets per port, battery trend, local stats, boots,
neighbours, the gateway check, every finding and suggestion, and the limits
below. `--json` carries all of it per node (`expected_interval_seconds`,
`expected_interval_source`, `stale_after_seconds`, `offline_after_seconds`,
`verdict`, `findings`, `importance`, `suggestions`, `metrics`), plus `failures` (per source or node)
and `refresh` (`refreshed`, `no_region`, `skipped_rows`).

**Verdict.** `crit` if any rule below says so, else `warn` if any does, else
`ok`; `unknown` when there is no history and no last-seen time at all. Each
node is judged against its own expected interval `E` and the stale and offline
thresholds it gives, exactly as in [`mesh status`](#mesh-status); a history
refreshed by this run already counts (it replaces a template or role default,
never `--expected-interval`). These are heuristics, not firmware limits:

| Rule | Warn | Crit | Why |
|---|---|---|---|
| not heard (history or `mesh status`) | over its stale threshold (at least 2 h) | over its offline threshold (at least 24 h) | `mesh status`'s own thresholds for the node |
| never heard in the covered hours | covered hours over its stale threshold | over its offline threshold (fewer: `unknown`, not heard yet) | a node expected every 6 h may be unheard for a few hours of history |
| battery (newest reading within 24 h, or within its stale threshold when longer; 0% and external power ignored) | at or below 20% | at or below 10% | as `mesh status` colours it |
| battery trend (6+ readings over 12+ h) | falling 10 points a day or faster | | a node that will be flat within days |
| one gateway only (20+ receptions) | yes | | one gateway failing loses the node |
| boots in the window | 3 or more per 7 days (3 for any window up to a week, 13 for 30 days) | | crashes or brown-outs |
| mean channel utilization | over 25% | over 40% | firmware delays sends above 25% |
| mean transmit air utilization | over 5% | over 10% | 10% is the common duty-cycle limit |
| longest run of silent covered hours | 5 `E` or more, at least 6 | | outages hidden by a fresh last-seen (as long as the offline rule, so a few lost packets of a slow node do not count) |

**Importance** (`high` from 5 points, `medium` from 2, else `low`) counts what
our other nodes (the active database nodes and any `NODE` asked for) would lose
without the node: 3 if it is an MQTT gateway (it uplinks its own packets or one
of ours, or its gateway check saw it uplink anything); 3 per node of ours it is
the only gateway of (with 20+ receptions); 2 per node of ours whose busiest
relay byte is unambiguously its own and carried at least half of that node's
relayed receptions (20+); 1 for a router role (`ROUTER`, `ROUTER_LATE`,
`ROUTER_CLIENT`, `REPEATER`).

**Suggestions** are worded as such; nothing is ever changed on a node:

| Suggestion | When |
|---|---|
| lower the hop limit to `max(3, most hops seen + 1)` | its `HopStart` is above that, from 20+ receptions with a hop count |
| longer telemetry interval | more than 2 telemetry packets an hour on a channel busier than 25% |
| longer position interval or smart position | more than 2 position packets an hour |
| check the role | a `CLIENT_MUTE` whose id byte is the busiest relay of one of our nodes (a byte collision, or the role is not what it reports) |
| check a router's placement | a router role uplinked by fewer than 3 gateways (20+ receptions) |
| another router within its reach | one relay byte carried 80%+ of its relayed receptions (20+) |

**How the numbers are computed, and their limits.**

- A *reception* is one `PacketReports` row: one packet uplinked by one MQTT
  gateway. Whether the gateway heard it over radio or MQTT cannot be told, so
  "heard by" means "uplinked by".
- *Direct* means the last transmitter (`RelayNode`, the last byte of its id)
  is the node itself; another node with the same last byte relaying it counts
  as direct too (1 in 256 per relay).
- *Hops* are `HopStart - HopLimit`, and only decoded packets
  (`PacketsParsed`, joined by packet id) carry `HopStart`: in the data seen
  so far a few percent of the receptions. The hop counts are that sample (the
  `decoded` share is shown), and the hop limit is the node's most common
  `HopStart`.
- *Relays* are known by their last id byte only; a byte is named as a node of
  ours only when exactly one has it, and then as "likely".
- *RSSI* is shown as lorastats gives it, a positive number; in the data seen
  it rises with SNR (as `RSSI + 256` would), so it is not converted to dBm and
  no rule uses it.
- Packets per hour count distinct packet ids per covered hour; telemetry and
  position rates and the battery readings come from decoded packets, so the
  rates are lower bounds.
- Battery trend is a least-squares slope of the telemetry battery readings in
  the window.
- lorastats times are Warsaw local time; a reception in the repeated hour of
  the autumn DST change may be filed an hour early.
- lorastats keeps about a day or two: what is older comes from the local
  history, so a node first refreshed today has today's data only.

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
  `--no-reconnect`, `-y`/`--yes`, `--json`) in addition to its own `--ref`
  -- including the admin-key-rotation refusal above: bootstrapping a node
  whose recorded key already backs an admin ref is refused the same way,
  with no bypass flag.
- `import` registers a public key you already hold, without touching a
  device. It validates length and canonical base64, runs the weak-key
  audit, and refuses a key already registered under a different reference
  unless `--allow-alias` — except when that other reference is one of
  `mesh adopt`'s own `observed-*` refs, which is not a collision to
  refuse but exactly the rename this command performs (see
  [`observed-*` rows](database.md#observed--rows)). Three flags each gate
  exactly one refusal, independently of one another: `--overwrite` allows
  replacing an existing ref's differing key material, `--allow-alias`
  allows registering a key already authorized under another ref, and
  `--allow-weak` allows a key that fails the weak-key audit to be
  registered anyway -- except an all-zero or small-order key, which no
  flag ever authorizes. `--dry-run` runs every one of those checks and
  reports the outcome (including a refusal) without registering anything,
  matching `provision`/`adopt`/`admin bootstrap`'s existing `--dry-run`
  convention.
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
| `--backup-dir` (`backup`, `restore`) | Directory backups are stored under/read from. Defaults to a `backups/` directory next to the database (`data/backups` for the default `data/nodes_db.ods` path). Never affects where the known-good copy lives (see below) — that's always the database's own default-resolved location |
| `--retention` (`backup`) | Number of backups to retain (default: 20) |
| `--list` (`backup`) | List existing backups instead of creating one; also reports the known-good copy's timestamp, when one exists |
| `--known-good` (`restore`) | Restore the known-good safety copy instead of naming a `BACKUP` path — mutually exclusive with it. Refused, before touching the database, when the copy's recorded provenance is not verified (see [Recovering from a bad hand-edit](database.md#recovering-from-a-bad-hand-edit)); a `BACKUP` path is never provenance-checked |
| `-y`/`--yes` (`restore`, `forget`) | Assume yes to the confirmation |
| `--json` | Emit JSON instead of human text |

- `verify` layers cross-reference checks, a weak-key audit over every key
  row, and alias-aware cross-fleet duplicate detection on top of the
  schema validation that already happens at load. Because `mesh admin
  bootstrap --ref LABEL` deliberately files one physical node's key under
  both `<node_id>_pub` and `<LABEL>_pub`, a duplicate group is
  **critical** only when it spans two or more **distinct real nodes** —
  the CVE-2025-52464 vendor key-cloning signature. A node-plus-label
  group is an informational alias warning. Separately, an admin key
  that is authorized on more than one node but has never been given a
  real ref via `mesh admin import` (an `observed-*` ref, or legacy
  `unregistered_admin_keys` material) is its own **warning**,
  `unimported_admin_key` — one admin key shared across many nodes is
  the normal fleet setup, not a clone signature, so it never raises
  `verify`'s exit code above what `--strict` already does for a bare
  warning. A `Keys` row whose `owner_node_id` is an existing node's id
  written in another case (`DEADBE01` for node `deadbe01`) is an
  **error**, `non_canonical_node_owner`: lookups by node id are exact, so
  `mesh provision` would never find that key as the node's own and would
  refuse the node as a key clone.
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

## `mesh peers`

```bash
mesh peers --port /dev/ttyUSB0            # report what is missing
mesh peers --port /dev/ttyUSB0 --apply    # write it
mesh peers --host 192.168.1.20 --apply --json
mesh peers --port /dev/ttyUSB0 --apply --prune-archived   # also unfavorite archived nodes
```

Makes the connected device know the rest of your fleet and keep it
favorited. Every active (non-archived) node in the database, except the
device itself, is sent to the device as a **contact** (id, names, hardware
model, role and the public key the Keys sheet records for it) and marked
**favorite**. A device only keeps the nodes it has heard recently and
evicts the rest; a favorite is never evicted, which matters most for
routers and base stations that must always reach, and hold the keys of, the
whole fleet.

Without `--apply` it only prints what is missing. With `--apply` it writes
and then reconnects and re-reads the device, so a write the firmware
silently dropped is reported (exit code 5), like `mesh provision`. It is
idempotent: a second run finds nothing to do. The database is only read.

Three cases are reported and deliberately left alone: a node with no public
key in the Keys sheet cannot be added as a contact (it is still favorited if
the device already holds it under a key that passes the same weak-key audit;
otherwise it is reported like a weak key and not favorited); a node the device
holds under a *different* public key is not overwritten — that is either a
stale database or a spoofed identity, for you to decide (`mesh adopt` re-reads
the device); and a node whose recorded public key fails the weak-key audit
(the structural checks and known-bad-keys blocklist of `mesh db verify`) or is
shared with another node is neither added nor favorited, because a favorite is
never evicted — run `mesh db verify`, then re-key the node (`mesh provision
--force-regenerate-key`). A run that leaves only such cases says so instead of
reporting the peers in sync; its exit code stays `0`.

`--prune-archived` also unfavorites every node archived in the database
(`mesh db forget`) that the device still has favorited, so the device may
evict it again. It only unfavorites: the device keeps the node and its key
until it evicts it or you remove it by hand, and the device's own node is
never touched. Without `--apply` it is only reported; an unfavorite the
device did not keep is reported after the read-back ("still has …
favorited", exit code `5`). The `sync_peers` step of `mesh provision` never
prunes.

Takes the same connection flags as `mesh provision` (`--port`,
`--ble-address`, `--ble-scan`, `--host`, `--interface`, `--timeout`,
`--ble-scan-timeout`) and `--json`. Run it once per device; to do it as the
last step of every provisioning run, leave `sync_peers: true` (the default) in
the template ([configuration](configuration.md)).

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

Exit code 2 (`CONFIG`) also covers command-line usage errors, which
click reports with a `Usage:` line: an unknown option, a missing
argument, or a node id that does not parse (`mesh status --node`,
`mesh adopt --node-id`, `mesh db forget`).

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
