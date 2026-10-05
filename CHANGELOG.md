# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Single `mesh` console script (distribution `meshprovision`) with seven
  subcommands/subcommand groups: `init`, `provision`, `status`, `admin`,
  `db`, `adopt`, and `template`.
- `mesh init`: creates whatever first-run artifacts (`.env`,
  `config/template.yaml`, `data/nodes_db.ods`) are still missing --
  prompts once for `MESHPROVISION_CONTACT`, the one setting with no
  default, unless `--contact` is given; `--yes`/`--json` make it fully
  scriptable. Only ever creates what is missing, so it is safe to re-run.
  The database is always created empty (never copied from
  `data/nodes_db.example.ods`, which carries fake illustrative rows). Any
  `mesh` command run interactively now offers this same wizard whenever
  setup is incomplete, before the command it was actually asked to run
  gets a chance to fail with a "file not found" error; the offer never
  fires for a help-only invocation, for `mesh init` itself, or when
  `--non-interactive`/a non-TTY stdin applies. The two example files
  `mesh init` copies moved from `.env.example`/`config/template.example.yaml`
  into `src/meshprovision/examples/`, so they ship inside every
  `pip`/`pipx` install rather than only a source checkout.
- `mesh provision`: Serial/BLE/TCP transports with an explicit selection
  priority, FACTORY/PROVISIONED/FOREIGN detection, a pure change planner that
  makes `--dry-run` exact, drift repair, and transactional writes verified by
  read-back.
- `mesh status`: strictly read-only health reporting, merging loranet.pl's bulk
  `nodes.json` dump with per-node lorastats.pl queries; `rich` table and
  `--json` output, `--watch`, and configurable online/stale/offline thresholds.
- `mesh admin bootstrap | import | list`: admin-key custody for 0-3 inbound
  admin nodes, including pending cross-authorization reporting.
- `mesh admin import --dry-run`: preview a registration's outcome (weak-key
  audit result, duplicate-key collision, `--force` overwrite) without
  actually registering anything, matching `provision`/`adopt`/`admin
  bootstrap`'s existing `--dry-run` convention.
- `mesh db verify | backup`: schema, cross-reference and weak-key verification,
  plus timestamped backups with retention.
- `mesh db restore`: restore the database from a backup, holding the
  cross-process write lock for the whole operation (unlike `backup`, which is
  deliberately lock-free) and confirming the restored file actually loads
  before reporting success.
- `mesh db list`: offline counterpart to `mesh status` -- a plain dump of the
  `Nodes` sheet's own content, with no device connection or external data
  source involved.
- `mesh template validate`: a sixth subcommand group. Validates the
  configured template file with no database or device needed, letting a
  template failure be the command's own real result rather than the
  degraded-to-a-warning treatment `mesh db verify`'s own template
  cross-check deliberately gives it.
- `mesh db forget`: archives (soft-deletes) a node via a new
  `archived_at` column -- the row (including `authorized_admin_keys` and
  `notes`) is never deleted, so audit history survives. An archived node
  is excluded from `mesh status`'s default report (an explicit `--node`
  request for it still wins) and refused outright by `mesh
  provision`/`mesh admin bootstrap`/`mesh adopt`, with no `--force`
  bypass. `mesh db list` shows an `Archived` column/field for every node
  either way.
- `mesh adopt`: strictly read-only inventory of an already-configured,
  already-deployed node -- connects like `mesh provision` but never writes
  to the device, and records live names, admin keys, firmware version,
  region, role, and BLE PIN as a new `management=observed` node. A new
  `management` column on the `Nodes` sheet (`template`/`observed`, default
  `template`) gates `mesh provision`/`mesh admin bootstrap`: touching an
  observed node now requires an explicit `--enroll`, checked before any
  admin-key resolution and before `--dry-run`'s early return. Every admin
  key the device reports now gets a real `Keys` sheet row: one already
  registered resolves to that ref, and one that isn't is auto-filed under
  a synthetic, content-addressed `observed-<fingerprint>` ref (`mesh
  admin import`/`mesh admin bootstrap` reject a human-chosen ref starting
  with `observed-`, and treat a collision against one as the rename it
  is, not a refusal) rather than left dangling on the now-legacy
  `unregistered_admin_keys` column. `mesh adopt` also records the node's
  own keypair (public half always, private half when the device exposes
  it), so `public_key_ref`/`private_key_ref` resolve. An unregistered key
  is still reported by fingerprint only by default; `--show-admin-keys`
  is the one deliberate exception, printing the `observed-*` ref
  alongside a paste-ready `mesh admin import` command to rename it. The
  same cloned key observed on two devices now collapses to one shared
  `observed-*` row both authorize, so `mesh db verify` gained a dedicated
  check (any `observed-*` ref shared by 2+ nodes) alongside its existing
  `unregistered_admin_keys`-based one for not-yet-re-adopted data.
  Re-adopting fully replaces `authorized_admin_keys` with current
  live reality (unlike `mesh provision`'s narrow-only rule for a
  template-managed row); re-adopting an already-`management=template` node
  is refused unless `--force`, with an explicit demotion warning.
- `mesh status` now shows each node's `management` mode (`template` or
  `observed`) -- a new `Mgmt` console column and a `management` key in
  `--json`'s per-node `database` object -- so a fleet mixing
  template-managed and adopted-but-not-yet-enrolled nodes is distinguishable
  without opening the `.ods` by hand.
- Hand-editable ODS database (`Nodes` + `Keys` sheets) written with odfpy
  directly: OpenFormula formulas for every derived column, dropdown content
  validation generated from the installed protobuf enums, a frozen header row,
  per-column header comments, and atomic writes with automatic backups.
- Canonical `NodeId` value object normalizing the four Meshtastic id forms, a
  `hw_model` -> chipset lookup, protobuf enum <-> name mapping, and a dedicated
  exception hierarchy rooted at `MeshprovisionError` with mapped exit codes.
- Pydantic template and settings models, with byte-accurate name-length
  validation (4-byte `short_name`, 39-byte `long_name`) and namespace-capacity
  computation, warning and exhaustion handling.
- TTL disk cache wrapping every outbound HTTP request, with TLS verification,
  timeouts, and retry with exponential backoff on 5xx/network errors only.
- `data/nodes_db.example.ods` plus the committed, deterministic generator
  `scripts/generate_example_db.py`, and `scripts/update_known_bad_keys.py`.
- Packaging, lint/type/test configuration, pre-commit hooks, a 3.11/3.12/3.13
  GitHub Actions CI matrix with a package-build check, a tag-triggered release
  workflow, and Dependabot for `pip` and `github-actions`.
- `all` extra (`pip install -e ".[all]"`), a self-referential alias for
  `[ble,dev]` together, for a one-shot full development install.
- `build` and `twine` added to the `dev` extra, so `pip install -e ".[dev]"`
  is now enough to run the packaging checks (`python -m build`,
  `twine check dist/*`) locally, matching the CI `package` job.
- Documentation covering installation, the template and `.ods` walkthroughs,
  every command, the security model, and Linux Mint troubleshooting: a
  landing-page README plus a `docs/` directory (see `### Changed` below).
- `-v`/`--verbose` (repeatable, global): `-v` raises this tool's own logs to
  `DEBUG`; `-vv` additionally unmutes `meshtastic`/`httpx`; `-vvv` also
  unmutes `bleak`/`httpcore`/`urllib3`. An explicit `--log-level` still wins.
  Every connect (serial/BLE/TCP, including `mesh adopt`, which previously
  printed nothing at all between device selection and its report) now prints
  a `Connecting over ...` line and, while the connection is in flight, a
  `still connecting... Ns / Ms` heartbeat every 10 seconds -- always on, not
  gated behind `-v` -- so a stalled BLE connect (which can silently block for
  several minutes inside the `meshtastic`/`bleak` libraries' own re-scans and
  timeouts) is now visibly still alive rather than indistinguishable from a
  hang.
- `mesh adopt --from-backup PATH`: adopt a node from an exported Meshtastic
  app config backup instead of a live connection, for a node you own but
  can't currently reach -- no device interface is ever opened. Repeatable;
  accepts a `.cfg`/`.yaml` `DeviceProfile` (Radio Config -> Backup & Restore
  -> Export in the app, or `meshtastic --export-config`'s YAML), a node-db
  JSON export (Settings -> Export node database), or one of each -- format
  is auto-detected, and the two are complementary: a `.cfg` carries names,
  full config, the node's own keys, and any admin keys, but no node id, hw
  model, or firmware version; a node-db export carries exactly those three
  plus `myNodeNum`, but no private key, admin keys, region, or channel. A
  backup never asserts its own node id with authority, so it is resolved,
  in order, from an explicit `--node-id`, a `Keys` sheet public-key match,
  or a paired node-db export's `myNodeNum`; two of those disagreeing is a
  refusal (new `NodeIdentityError`) unless `--force` is passed, and when
  none resolve anything, an unmatched loranet long-name lookup (skippable
  with `--no-lookup`) is offered only as a `--node-id` hint, never used to
  adopt. A `.cfg`'s `channel_url` is decoded and, only when its primary
  channel's PSK is the full 32-byte AES256 form, recorded as a new
  `<node_id>_psk` `Keys` sheet row (`--no-channel-psk` to skip) -- finally
  giving the `channel_psk_ref` derived column, present since the schema's
  first version but never before written, a writer; a `.cfg`'s
  `fixed_position`, when set, fills `gps_lat`/`gps_lon`/`gps_alt`. Both, like
  `hw_model`/`firmware_version`, are only ever added on re-adopt, never
  used to blank a value a previous adopt recorded. Because a `.cfg`/YAML
  backup is the one place `mesh adopt` ever sees a node's own private key
  without touching the device, its keypair is now also run through the
  weak-key audit (consistency check included) -- the live-device path has
  never done this, since the report only ever audited admin keys. New
  `meshprovision.provisioning.backup` module and `BackupParseError` exit
  code (2, `CONFIG`).
- A single, stable known-good safety copy of the database
  (`data/backups/nodes_db.known-good.ods`), refreshed by
  `meshprovision.db.atomic_writer.refresh_known_good` on *every*
  successful database load anywhere in the codebase -- not just a write,
  and not just through `mesh db backup`/`--retention`'s existing
  timestamped rotation, which it sits alongside without being part of
  (its name never matches that rotation's glob, so it's never pruned or
  listed by it). Best-effort: a refresh failure (full disk, a read-only
  backup directory) is logged and swallowed, never breaks the read it
  rode in on. `mesh status`/`mesh db list`/every other read-only command
  now write this small side-channel file on a changed database (a no-op
  `stat()` otherwise) -- the live database file itself is still never
  written by any of them. When a load fails outright (a hand-edit that
  breaks the schema, corrupts the ODF zip, or introduces a duplicate
  row), the resulting error's hint now names the known-good copy's
  timestamp and `mesh db restore --known-good`, a new flag that restores
  it without needing to know its path. `mesh db backup --list` also
  reports its timestamp when one exists.
- A template `is_unmessagable` field ("infrastructure node" -- a sensor or
  repeater that should never show up as a target for direct messages),
  written through the same `Node.setOwner()` admin message as
  `short_name`/`long_name`. `User.is_unmessagable` is a protobuf field on
  `meshtastic.protobuf.mesh_pb2.User`, not on `config.device`, so it has
  no section of its own -- it slots into the existing name-write (owner)
  phase instead, verified alongside `short_name`/`long_name`. Omitted or
  `null` (the default) leaves the device's current value untouched; there
  is no CLI override, unlike the names. A planned change is previewed like
  the names: an `owner.is_unmessagable: <current> -> <desired>` line in
  `mesh provision --dry-run`, `current_is_unmessagable`/
  `desired_is_unmessagable` under `name_change` in the `--json` plan, and
  an `owner: N field(s)` count (names included) in the plan summary.
- The `meshtastic` dependency now pins to a specific commit
  (`be366660828b5a54469e703209a10aa954927791`) on `meshtastic/python`'s
  unreleased `master` branch instead of the PyPI release (`>=2.7.11`,
  still the latest tagged release) -- the only way to get
  `Config.SecurityConfig.packet_signature_policy`, a firmware 2.8
  protobuf field not in any tagged release yet. Re-evaluate once an
  official 2.8-compatible release lands. The pinned protobuf knowing the
  field says nothing about the connected device's firmware: see the
  firmware gate on the template field below.
- A template `security.packet_signature_policy` field: firmware 2.8's
  XEdDSA packet-signing policy control
  (`PACKET_SIGNATURE_POLICY_COMPATIBLE`/`_BALANCED`/`_STRICT`), validated
  and canonicalized against the installed protobuf's own enum, following
  the same pattern as `device.role`/`lora.region`/etc. Omitted or `null`
  (the default) leaves the device's current value untouched. Only planned
  when the device reports firmware 2.8 or newer: older firmware drops the
  unknown field, so the write could never be verified and the node would
  never be recorded. On firmware before 2.8, or an empty/unparseable
  firmware version, a change is skipped with a
  `field_unsupported_by_firmware` plan warning (shown by `--dry-run`, in
  the `--json` plan's `warnings`, and before a real run); a template value
  that already matches the device (e.g. `_COMPATIBLE`, the pre-2.8
  default) is a silent no-op.

### Changed

- A discovered `.env` is no longer refused for being group-writable when
  its group is the user's primary group and no other user is in that
  group (the default permissions under umask 002 on distros with per-user
  groups). World-writable files, foreign-group group-writable files,
  files writable by a primary group shared with other users (e.g.
  `users`; on LDAP/sssd hosts without user enumeration only local
  accounts are checked), files owned by another user, and anything that is
  not a regular file are still refused; a symlinked `.env` is judged by
  the file it points to. The check runs against the same open file that
  is then parsed, so the file can't be swapped between check and read,
  and the error lists each problem with the `chmod`/`chown` command that
  fixes it.
- The `Nodes`/`Keys` sheets are now always sorted -- on load, on every
  in-memory mutation, and on write -- instead of preserving insertion/
  hand-editing order. `Nodes` sorts by `long_name` (falling back to
  `short_name` when empty), case-insensitively and in natural/human order
  (`MT2` before `MT11`, not the reverse), tie-broken by `node_id`;
  archived nodes sort inline, not to the bottom. `Keys` sorts the same
  way on its own `key_ref`. This retires the previous "row order is
  never re-sorted, so hand-ordering survives a round trip" guarantee:
  `mesh db list`, `mesh status`, and the `.ods` file itself now always
  agree on one predictable order. See
  [`meshprovision.db.sorting`](src/meshprovision/db/sorting.py).
- `Nodes.management` now defaults to `observed`, not `template`, when a
  row's cell is blank. `NodeRecord.to_row()` always writes an explicit
  value, so a blank cell can only come from a row added by hand -- which
  is exactly what `observed` means: `mesh provision` leaves it alone
  until it's explicitly enrolled with `--enroll`, rather than silently
  enforcing the template on a device the operator only meant to record.
- Default logging verbosity dropped from `INFO` to `WARNING`, so a plain
  `mesh status` (and every other command) no longer prints per-request
  "fetching ..." lines to stderr. The `-v`/`--verbose` ladder shifted down
  to compensate: `-v` now raises this tool's own loggers to `INFO`
  (restoring the fetch trace), `-vv` to `DEBUG` plus unmuting
  `meshtastic`/`httpx`, `-vvv` also unmuting `bleak`/`httpcore`/`urllib3` --
  each `-v` reaches everything the old ladder needed one fewer `-v` for.
  The HTTP fetch log line itself now includes the request's query string
  (e.g. lorastats.pl's `?node=<hex>`), so the four lorastats.pl requests a
  `mesh status` run makes are no longer indistinguishable at `-v`.
- Documentation restructured: `README.md` is now a landing page (pitch,
  requirements, install, quick start, command cheat sheet, a docs index) and
  the full reference material -- installation details, configuration and the
  template walkthrough, the `.ods` database schema, every command's options,
  the security model, firmware 2.8 compatibility notes, deliberate spec
  deviations, and Linux Mint troubleshooting -- moved into topic pages under
  `docs/`.
- `mesh status`'s console table (`Timestamp` column) and summary caption now
  render in the machine's local timezone instead of UTC (the standard `TZ`
  environment variable overrides it); `--json` is unchanged -- still UTC,
  `Z`-suffixed, byte-identical across timezones and DST. The summary
  caption also gained a `data as of <source> <time>` clause per queried
  source, stating when that source's data was actually last fetched from
  the network (the original fetch time on a cache hit, never "now"), so a
  report served entirely from the HTTP cache doesn't read as freshly
  fetched; `--json` carries the same information, in UTC, as a new
  `data_as_of` object alongside `cache`.

- `mesh admin import --force` split into three independent flags:
  `--overwrite` (replace an existing Keys-sheet row), `--allow-alias`
  (re-point an admin ref already authorized on a different node), and
  `--allow-weak` (accept a key the weak-key audit flags, when the audit's
  hard blocklist doesn't already refuse it outright). The old single
  `--force` no longer exists; a script or alias using it needs updating.
- A template's `admin_nodes` list is now validated the same way `mesh
  admin import`'s own `--ref` argument always was: an entry that isn't a
  valid node reference, ends in a reserved suffix (`_pub`/`_priv`/`_psk`),
  or starts with the reserved `observed-` prefix now fails template load
  with an actionable hint, instead of loading successfully and only
  failing later -- confusingly, well after the fact -- the next time `mesh
  admin import` or a provision run touches that entry.
- Loading an empty, comments-only, or otherwise blank-after-parsing
  template file now raises immediately instead of silently applying every
  default as if the file had never been read.
- `mesh admin import`/`bootstrap`/`mesh adopt` now refuse to rewrite an
  admin key that is already authorized on another live, non-archived
  node ("admin-bearing") unless the operator explicitly re-points it;
  previously `mesh adopt --yes` alone (no `--force` needed) could silently
  replace such a key's Keys-sheet rows out from under the node that
  depends on it, and `mesh admin bootstrap --ref` could re-point an
  existing admin alias onto an unrelated device with no confirmation
  prompt naming the collision.
- A template's `position.fixed_latitude`/`fixed_longitude`/`fixed_altitude`
  are no longer accepted: meshprovision never actually applied them (they
  are not `PositionConfig` fields, and setting them only flipped
  `fixed_position` on the device without ever sending the coordinates), so
  a template that sets any of the three now fails to load with an
  actionable hint instead of loading and silently doing nothing with them.
  Set them with the `meshtastic` CLI's own
  `--setlat`/`--setlon`/`--setalt` instead.
- `mesh provision --rename` is now idempotent: if a node's recorded
  `short_name`/`long_name` already parse under the template's *current*
  `short_name_pattern`/`long_name_pattern`, `--rename` keeps them
  unchanged instead of always allocating a fresh pair. Previously,
  running `--rename` twice in a row on an already-conforming node would
  rename it a second time for no reason; a rename is now only allocated
  when the existing names no longer fit the current patterns (e.g. after
  a template change) or the node is new.
- `OdsDatabase.save()` now refreshes the known-good safety copy too, not
  just `load_database()`. This reverses an earlier judgment (a prior
  round deliberately deferred the known-good refresh to the next load):
  that left the copy one write behind, so `mesh db restore --known-good`
  could silently lose any `save()`s that landed between the last load
  and a subsequent corruption. `save()`'s own pre-write backup (already
  taken on every call) always protected the immediately-preceding
  version regardless; this closes the gap for every save before that.
  A read-only command that loaded the database just *before* such a
  save, and finished after it, no longer puts the copy back to the
  pre-save version: a refresh never replaces a copy that already
  reflects a newer write to the database.

### Fixed

- When `mesh provision` stopped early, its report could leave sections
  out or describe them wrongly. A failed settings-transaction begin or
  commit printed a single failure line, with no word on which sections
  were or were not written. A stop after the commit (a failed mid-plan
  reconnect or identity check), or a failure before it, never mentioned
  a held-back `default_channel` in the "Not written" list. Now every
  section that was never sent is listed as not written. After a failed
  commit, each section already sent is reported unconfirmed (the device
  may or may not have saved it) and is not re-read. With
  `--no-reconnect`, `security` is sent inside that transaction, so it is
  now counted as possibly applied. Whenever `security` was sent but its
  `is_managed` was never confirmed (that case, a failed security write,
  or a failed final reconnect), a template that sets `is_managed` now
  gets a warning that the node may be locked to its admin keys, instead
  of nothing. A commit failure hidden by another error is now logged as
  a warning.
- `mesh provision` wrote `default_channel` to a primary channel the
  device reported as disabled -- the role the meshtastic library gives a
  channel it never received, and one the plan already reads as having no
  settings. The channel write sends the whole channel, so it could
  overwrite the real primary channel with a near-empty one, and the
  section never verified, so every run proposed it again. When the
  device reports a missing or disabled primary channel, the plan now
  leaves `default_channel` out with a `primary_channel_unavailable`
  warning (shown by `--dry-run`, in the `--json` plan's `warnings`, and
  before a real run); everything else, including `security`, is still
  written and the node is recorded. The channel write itself also
  refuses such a channel before anything is sent, as a backstop. A
  missing primary channel was also wrongly treated as a possibly-sent
  write; it is now "not written" too.
- Re-adopting a node whose public key changed, from a source with no
  proven private key (a `--from-backup` node-db export, a device that
  reports only its public key, or one whose reported private key does not
  derive its public key), recorded the new `<node_id>_pub` but left the
  old `<node_id>_priv` in place: `mesh adopt` exited 0, `mesh db verify`
  then failed on the inconsistent keypair, and `private_key_ref` pointed
  at the wrong key. `mesh adopt` (including `--dry-run`; `--force` does
  not bypass it) now refuses when an existing `_priv` row would not
  derive the public key being recorded, and never deletes or overwrites
  that row itself -- it may be the only copy of the old key. A source
  that reports a proven private key still replaces both rows. The
  "`_priv` already holds different key material" warning is also no
  longer printed for an unproven private key, which is never written.
- A `name_suffix_alphabet` with characters that differ only in case
  (e.g. `"aA"`) loaded fine, but names are compared case-insensitively,
  so each such pair yielded one usable name, not two: the reported
  capacity (`name_min_capacity` check, utilization warnings) overstated
  the namespace and allocation could hit "namespace exhausted" early.
  Such an alphabet is now a template-load error naming each colliding
  pair, as is a character that case-folds to several characters (`ß` ->
  `ss`, ligatures like `ﬁ`), which could make two different suffixes
  collide. A template that loaded before may now be refused; the default
  base36 alphabet is unaffected.
- `node_key_admin_refs` counted `authorized_admin_keys` on any
  non-archived node, including `OBSERVED` (adopted-but-not-enrolled)
  rows, as evidence a key is admin-bearing. Since `mesh adopt` records
  whatever a connected device self-reports as its own admin keys, and
  an admin's public key is broadcast on the mesh, any device could claim
  it and permanently pin that key's admin status — blocking every
  remediation path (`--force-regenerate-key`, the weak-key audit, the
  CVE-2025-52464 firmware window, a missing-key capture) for the node
  that actually holds it, with no flag to override and no recourse short
  of `mesh db forget`ing the adopted stranger node. Narrowed the
  evidence to `TEMPLATE`-managed rows only — what `mesh provision`
  itself wrote to a device, under operator control. `template.admin_nodes`
  evidence and `admin_custody.collect_admins` (display-only, `mesh admin
  list`) are unaffected.
- A node with no recorded key (`db_public_key is None`) but a complete,
  audit-clean live keypair fell through `_plan_node_keypair`'s branch
  order into a final no-op `else`, so its keypair was never captured into
  the database. Consequently `mesh admin bootstrap --ref ADMIN1` on such
  a node warned "No public key material available to register alias
  'ADMIN1'; skipping." and exited 0 without ever registering the alias.
  Security-adjacent: with no identity baseline recorded, a later device
  claiming the same node id with a different key would be accepted
  without comment. Added a first-capture branch that adopts the device's
  reported keypair (`origin=captured`) instead. A key already registered
  under another ref is still refused (`reason="capture"`), unless that
  ref is the one being bootstrapped with `--ref` -- the operator named it
  explicitly, and reaching this branch already proves the device holds
  the matching private key, so recording it rotates nothing.
- `mesh adopt`'s `adopted_record()` unconditionally overwrote `hw_model`
  and `firmware_version` from the current report, unlike the "empty is no
  new information" guard `role`/`region` already had. Unreachable from a
  live device (which always reports both truthily), but a `mesh adopt
  --from-backup` profile alone reports neither at all, so re-adopting a
  node from a `.cfg`-only backup would silently blank a value a previous
  (live or paired-node-db) adopt had recorded. Given the same
  non-clobbering guard as `role`/`region`.
- `mypy --strict` failed on a clean `pip install -e ".[dev]"` (including in
  CI, on all three supported Python versions) with `import-untyped` errors
  for `yaml` (`config/template.py`) and `google.protobuf.descriptor`
  (`provisioning/detect.py`, `provisioning/apply.py`). The `dev` extra was
  missing the `types-PyYAML`/`types-protobuf` stub packages mypy needs for
  those imports; a long-lived local venv that happened to have them
  installed separately masked the gap. Added both to `dev`.
- The stub fix above treated the symptom, not the hole: `PyYAML`,
  `protobuf`, and `pyserial` are imported directly by `src/` (`yaml` in
  `config/template.py` and `provisioning/backup.py`; `google.protobuf` in
  `provisioning/backup.py`, `provisioning/apply.py`, and
  `provisioning/detect.py`; `serial.tools` in `provisioning/discovery.py`)
  but were never declared in `[project.dependencies]` -- they only reached
  the environment as transitive dependencies of `meshtastic`. Had
  `meshtastic` ever dropped or re-scoped one, both the imports and the
  mypy gate would have broken again. All three are now declared directly,
  with version bounds matching `meshtastic`'s own. Added
  `tests/unit/test_declared_dependencies.py`, an AST-based guard that
  fails locally the moment `src/` imports something outside
  `[project.dependencies]` (an import guarded by `try`/`except
  ImportError`, like `bleak`'s, is exempt) or a mypy stub package drifts
  out of sync with its runtime counterpart.
- `mesh status`'s Short/Long columns (and the JSON `short_name`/`long_name`
  fields) rendered `-` for a node that had names on file in the `Nodes`
  sheet but wasn't reported by loranet.pl or lorastats.pl this run --
  those columns only ever consulted live observations, never the
  database. A node's name now falls back to its `Nodes` sheet row when no
  source reported one this run; a live-observed name still wins.
- Closing a device connection (`mesh adopt`, `mesh provision`, `mesh admin
  bootstrap`) could hang the process forever after the command had already
  obtained everything it needed. Root cause: a confirmed reentrancy bug in
  meshtastic 2.7.11's `BLEInterface` -- its `disconnected_callback`
  re-invokes `close()` on disconnect, including the disconnect `close()`
  itself just caused, and that second call can hang indefinitely on a GATT
  write against an already-torn-down client. `close_interface()` now runs
  the close on a background thread with a 3-second bound; if it does not
  return in time, a warning is logged and the command proceeds with its
  already-obtained result instead of hanging.
- `mesh --help` and every subcommand's `--help` no longer render the
  command's raw Google-style docstring verbatim, which used to dump
  developer-facing `Args:`/`Returns:`/`Raises:` sections (and leaked
  Sphinx cross-reference roles like `` :class:`~a.b.C` `` and rST
  literals like ` ``--flag`` `) straight into operator-facing help text.
  Help now shows only the docstring's prose, up through its first such
  section header, with roles and literals rendered as plain text.
- `mesh status`'s lorastats source no longer falls back to an unrelated
  record when no exact node-id match is found in a per-node query response;
  a non-matching record is now treated as "no observation" rather than
  filed under the wrong node's id. The unused, upstream-IP-ban-risking
  `fetch_region` bulk-dump method has been removed.
- Concurrent `mesh provision`, `mesh admin bootstrap`, and `mesh admin
  import` runs against the same database no longer silently discard each
  other's writes. An advisory sidecar file lock (`<database>.lock`) now
  serializes the load-modify-save cycle; a writer that cannot acquire it
  within `MESHPROVISION_LOCK_TIMEOUT` seconds (default 5) fails fast with
  `DatabaseLockedError` (exit code 4) instead of racing. `--dry-run` never
  takes the lock; read-only commands (`mesh status`, `mesh db verify`) are
  never blocked by it. Platforms without `fcntl` degrade to a documented
  no-op with a one-time warning, rather than failing outright.
- `mesh provision`'s post-write verification no longer crashes with an
  unhandled traceback if the device reconnects successfully but a
  subsequent read fails; it now reports the same safe "uncertain, database
  not updated" outcome as a failed reconnect, with a distinct message.
- Backup files are now written atomically (temp file, then renamed into
  place) instead of via a direct copy, so a crash mid-backup can no longer
  leave a truncated file indistinguishable from a good one. Backup
  pruning and listing now tolerate losing a race to a concurrent writer
  instead of aborting the operation that triggered them.
- `mesh db verify` now surfaces a hand-edited, LibreOffice-coerced text
  cell in its warnings list (including `--json`), not only in the log.
- Deleted `provisioning/repair.py`'s unused, already-diverged
  `build_repair_plan`/`repair_node`/`reconcile_record` functions (no
  production caller; `mesh provision` already covers drift repair via the
  functions that remain) along with a stale docstring warning that
  described a bug those functions no longer had.
- A `MESHPROVISION_LOCK_TIMEOUT` set to a non-finite value (`inf`, `nan`)
  no longer hangs `mesh provision`/`mesh admin` forever waiting on a
  deadline that can never be reached; it is now rejected the same as any
  other malformed value (see Security, below, for the follow-up that made
  this and other malformed values fail loudly instead of falling back).
- A genuine lock-acquisition failure unrelated to contention (e.g. the
  filesystem running out of advisory-lock records) is no longer
  mislabeled as "another mesh command is using the database" after
  waiting out the full timeout, and no longer names a stale process id
  left over from a previous, unrelated lock holder; it now fails
  immediately with an accurate error.
- `mesh db backup` runs that land within the same second (or race a
  concurrent backup) can no longer silently overwrite one another's
  output; backup filenames now carry microsecond resolution and a
  genuine collision fails loudly instead of clobbering. Existing
  second-resolution backup filenames still parse correctly.
- `mesh db verify` no longer aborts with an unrelated provisioning error,
  reporting zero database findings, when the configured template has more
  than 3 `admin_nodes` entries; that condition now degrades to a warning
  like every other template-loading failure, and verification of the
  database itself still runs to completion.
- `mesh status --source loranet` no longer requires `MESHPROVISION_CONTACT`
  to be set, since lorastats.pl (the only source that needs a contact
  string) is never queried on that path. Any invocation that resolves to
  include lorastats, including the default with no `--source` filter,
  still requires it exactly as before.
- `mesh provision`'s post-write verification no longer certifies a write
  as `CONFIRMED` for a device value the planner itself would consider a
  real mismatch (for example a live `1` read back where the plan desired
  `True`). The verification step now uses the same type-tolerant
  comparison the planner already used when building the diff, instead of
  a second, more permissive copy that had diverged from it and carried no
  test coverage.
- Orphaned backup and write temp files (`.{name}.tmp-{pid}-{uuid}`) left
  behind by a killed `mesh provision`, `mesh admin`, or `mesh db backup`
  process are now swept automatically, once they age past 24 hours,
  every time a new backup or write runs. The sweep is age-guarded rather
  than immediate so it can never remove a live, currently-in-progress
  backup's temp file.
- `mesh admin list`'s table now shows each admin's weak-key audit result
  (`-`, `clean`, `warning`, or `compromised`, the last highlighted) in a
  new `Audit` column. This information was already computed and already
  present in `--json` output; only the default human-readable table
  omitted it.
- A live admin key revoked by the weak-key audit while `template.admin_nodes`
  is empty (the project's documented default template shape) no longer leaves
  `mesh provision` reporting the same `admin_keys` drift on every subsequent
  run, permanently, nor `mesh admin list` crediting the revoked key with
  authority over the node. The `Nodes` row's `authorized_admin_keys` is now
  narrowed to drop the revoked ref instead of being left stale -- not
  rebuilt, since a live admin key with no `Keys` sheet row still cannot be
  named. `--json` output gains a new `key_plan.removed_admin_key_refs`
  field. (Clearing the field wholesale on every run was considered and
  rejected: it would have reported zero admins on a node that still has
  two working, healthy administrators.)
- If a device write during `mesh provision` succeeded and was verified, but
  the database save that should have recorded it then failed (the realistic
  case being the disk filling up while serializing the `.ods`), the run now
  reports that the device and the database disagree for that node, rather
  than surfacing only the underlying `OSError`. The message states plainly
  that the device write was confirmed, the database was not saved, and the
  two now disagree; when the run also generated a new node keypair, the
  message additionally names `--force-regenerate-key`, since a later run
  will never adopt a device key the database has never seen. **This save
  failure now exits with code `4` instead of `1`.**
- Template warnings (for example, an option named in both
  `enabled_options` and `disabled_options`) are now routed through the
  same styled warning path as database integrity warnings, instead of
  going only to the structured log. Previously, a run at `--log-level
  ERROR` dropped a template warning entirely, while a database warning at
  the same level still reached the operator.
- A live admin key that is healthy (passes the weak-key audit) but simply
  not named in a non-empty `template.admin_nodes` is no longer silently
  dropped from the device on apply. `mesh provision`'s plan now reports it
  (`security.admin_key: revoke [...] (not in template.admin_nodes)`, both
  in `--dry-run` output and `--json`), the same way a weak-key-audit
  removal already was -- previously, an admin key an operator never asked
  to remove (for example a trusted collaborator's) could be wiped with no
  warning anywhere.
- `mesh provision --allow-weak-admin-key` no longer claims a weak admin key
  "will be removed" when the key is both template-named and already live on
  the device -- the override re-authorizes it in place, so no device write
  happens, but the plan's `--dry-run`/`--json` output previously reported a
  removal that would not occur. This was a false statement in the tool's
  own security audit trail on a security-relevant field, not a data-loss
  bug: the device and database always ended up where the operator asked.
- A database-save failure during `mesh provision --enroll` now tells the
  operator up front that the node needs `--enroll` again on retry. The
  previous hint predated `--enroll`/`management`, so a literal re-run
  hit `NodeNotEnrolledError` a second time before reaching the right fix.
- `mesh provision`/`mesh repair`'s admin-key drift detection no longer
  reports a false `ADMIN_KEYS` drift for a key registered under more than
  one `Keys` sheet reference (for example `mesh admin bootstrap --ref
  LABEL`'s deliberate dual filing). The lookup used to invert `{ref:
  material}` into `{material: ref}`, silently keeping only one alias; it
  now preserves every matching ref, the same alias-aware logic `mesh
  adopt` already used.
- `long_name`'s enforced limit is now 25 UTF-8 bytes, down from 39, matching
  firmware 2.8's tightened limit. A template that validated cleanly under
  the old limit could render a name that firmware 2.8 silently truncates on
  write. 25 bytes is safe for 2.7.x devices too.
- `mesh adopt` no longer reports a node as "not vulnerable" to
  CVE-2025-52464 when its firmware version is missing or unparseable; it
  now warns that the vulnerability status is unknown, matching the same
  function's existing handling of an unmappable region or role.
- `mesh provision` now actually records a device's own reported public
  key into the `Keys` sheet when the plan decides to adopt it rather than
  overwrite it (`security.public_key: adopt the device's reported key` in
  `--dry-run` output, firmware issue #7449's "a restored key can silently
  fail to persist" case). Previously this decision was only ever
  described, never applied: the stale `Keys` sheet row was left in place
  indefinitely, and every subsequent run re-reported the same
  `device_key_differs_from_db` warning and re-triggered an unnecessary
  device reboot. The device's own keypair is never written back to the
  device in this case -- only the database is corrected to match what the
  device already holds.
- `mesh provision --allow-lockdown` can now actually complete
  successfully. The post-write verification pass looked up every
  `security` scalar field (`is_managed`, `serial_enabled`,
  `debug_log_api_enabled`, `admin_channel_enabled`) through a lookup that
  is documented to always return nothing for that section, so a
  successful lockdown write was unconditionally reported UNCONFIRMED and
  the database was never updated, regardless of whether the device write
  actually succeeded.
- `MESHPROVISION_LOCK_TIMEOUT`'s default is now 60 seconds, up from 5.
  The write lock is deliberately held for the whole device provisioning
  conversation, not just the database save, but the old default was far
  shorter than a realistic transaction -- two operators (or one
  operator's scripted loop) provisioning two completely unrelated
  devices concurrently, this project's own normal fleet workflow, would
  spuriously collide on `DatabaseLockedError` on almost every run. The
  error's hint now also names the env var and its current value.
- `mesh status` now surfaces when a data source successfully fetched but
  silently could not parse some of the entries it returned (a new
  `skipped_entries` map in `--json`, a summary/caption line, and
  participation in the degraded exit code) -- previously a mass
  parse-failure (an upstream schema change dropping a large fraction of
  the fleet, for example) was indistinguishable from those nodes simply
  being offline unless an operator was tailing logs at WARNING.
- `mesh db verify`'s cross-fleet duplicate-key classifier no longer
  requires both colliding keys to already have a `Nodes` sheet row before
  rating the match CRITICAL -- registering an admin key via `mesh admin
  import` ahead of adopting the device it belongs to is this project's
  own documented onboarding order, and a genuine CVE-2025-52464 clone
  between two such not-yet-adopted devices was being silently downgraded
  to an informational alias warning.
- A mismatched admin keypair now exits `mesh db verify` at severity
  `critical` (exit 6) instead of `error` (exit 4), matching the severity
  `weakkeys.audit_keypair`'s own (unreached) consistency check already
  gives the identical condition.
- `mesh adopt` now actually audits live admin keys against the weak-key
  blocklist -- previously the blocklist was loaded and threaded through
  on every run but never used, so the inventory report checked firmware
  vulnerability but said nothing about a compromised or structurally weak
  admin key already on the device.
- `mesh admin bootstrap`'s pending-cross-authorization report no longer
  conflates two distinct facts when rotating an existing `--ref` onto a
  new device: it could print a false "authorize X on node Y" claim for
  an authorization that was already satisfied, while silently dropping
  the genuine pending one. Not reachable on a first-time bootstrap --
  only when re-bootstrapping an existing ref.
- Several `KeyMaterialError` catch sites (`mesh db verify`'s weak-key
  audit, `mesh adopt`'s admin-key inventory and audit warnings, the
  live-admin-key-compromise check) no longer report a bare "malformed
  key material" string -- the actual reason (wrong length, bad
  encoding, non-canonical base64) is now included, and a NodeDB public
  key that fails to decode after a write is reported as such instead of
  silently falling back to a possibly-misleading fingerprint.
- `mesh adopt` now warns when a device reports an `hw_model` value its
  enum table doesn't recognize (for example, newer hardware this
  project hasn't added yet), instead of silently recording an empty
  `hw_model` indistinguishable from the device simply not reporting one
  at all -- matching the same warn-on-unmappable-value convention
  already used for `region`/`role` in the same report.
- Opening the database in LibreOffice Calc and saving -- even a no-op
  save, like resizing a column -- no longer breaks `mesh db verify`
  with every cell reporting as a garbled mix of its column's built-in
  description and its own value. LibreOffice rewrites a saved cell
  without the cached value the loader used to prefer, and reorders a
  cell's attached comment ahead of its text; the loader now reads only
  a cell's own text, never a comment attached to it. The same bug could
  silently splice a hand-added comment on a *data* cell into that
  cell's value instead of erroring; it no longer can.
- `mesh db verify`'s header-mismatch error no longer dumps two raw
  Python tuples (every column name and description concatenated into
  one wall of text once the bug above is hit) as its only diagnostic.
  It now renders an aligned table of what was expected against what was
  found, collapsing matching columns to one summary line, and a
  best-guess hint identifying a deleted, inserted, renamed, or
  reordered column plus how to roll back. A database with both sheets'
  headers mangled now reports both in one run instead of only the first.
- `--log-level debug` could never actually surface `meshtastic`'s or
  `bleak`'s own progress logging: the third-party noise floor used
  `max(numeric_level, WARNING)`, which -- because a lower number means
  more verbose -- can only ever raise the effective minimum, never lower
  it, so requesting more detail than WARNING had no effect on those two
  loggers. Fixed by the new `-vv`/`-vvv` staging described above; a plain
  `--log-level debug` with no `-v` still leaves them at WARNING, matching
  prior behavior exactly (see the `Added` entry for what changed).
- `Ctrl-C` during a command (most notably a long, silent BLE connect) used
  to exit with no message at all, indistinguishable from a hang or a crash.
  It now prints `Interrupted.` to stderr before exiting, matching the
  existing declined-prompt (`click.Abort` -> `Aborted.`) behavior.
- A BLE connect failure raised directly by the `meshtastic`/`bleak`
  libraries themselves (`BLEInterface.BLEError`, `bleak.exc.BleakError` --
  for example "No Meshtastic BLE peripheral ... found" from the library's
  own internal re-scan) used to escape as a raw, unredacted Python
  traceback instead of the hinted `ConnectionFailedError` every other BLE
  connect failure already produces. Both exception types are now caught
  alongside the others.

- A row's data past a blank-cell gap inside a giant ODS `table:number-rows-repeated`
  block could be silently dropped on load instead of raising, and a
  sheet with an implausibly large repeated-non-blank-row count (a sign of
  a corrupted or hand-mangled file) now fails to load with a clear error
  instead of being accepted and potentially exhausting memory.
- `mesh db restore` now validates the candidate backup file before
  overwriting the live database with it, instead of only discovering a
  malformed backup after the live file is already gone.
- `mesh status --watch` now tolerates up to 3 consecutive transient
  database read failures (a concurrent `mesh db restore`, a brief
  `EACCES` while permissions are being fixed) before giving up, keeping
  the last successfully-loaded report on screen and retrying, rather
  than exiting on the very first hiccup; the non-`--watch` single-shot
  path is unaffected and still fails immediately as before.
- A device reporting a `loranet.pl` `seenBy` topic value that couldn't be
  parsed as a timestamp is now counted and surfaced through the same
  field-coercion warning mechanism used elsewhere, instead of the field
  being silently dropped with no visible signal that data was lost.
- Fixed a case where `httpx.RequestError` subclasses other than the ones
  already handled (redirect loops, response-decoding errors) could
  escape a cached HTTP request as a raw, unredacted traceback instead of
  the project's normal wrapped/retried error handling.
- `mesh adopt` now also audits a live device's *own* reported keypair for
  weak-key findings, not only a `--from-backup` profile's recorded
  keypair, closing a gap where adopting a device directly could miss a
  compromised key `--from-backup` would have caught.
- CLI commands now log a full traceback at `DEBUG` (visible under `-vv`)
  for an unhandled `OSError`, matching the detail already logged for the
  project's own error types -- a permissions/disk-full/IO failure was
  previously reported to the operator with only a one-line message and no
  way to get more detail even with verbose logging enabled.
- The weak-key blocklist (`known_bad_keys.txt`) is now also searched next
  to the configured database file, in addition to the package/repo/CWD
  locations already searched. An installed (non-`-e`) `mesh` run invoked
  from any directory other than one happening to contain a `data/`
  subfolder previously could not find an operator-maintained blocklist
  file at all; its absence is now logged at `INFO` (previously `DEBUG`)
  with every location that was searched.

### Security

- The HTTP client no longer follows a redirect from an `https` URL to a
  plain-`http` one. Following it sent the request -- including the
  `User-Agent` carrying the operator's `MESHPROVISION_CONTACT` -- in
  cleartext, and cached the unauthenticated response body for the full
  cache TTL. Such a redirect now fails that source's fetch with an error
  naming the refused target (it is not retried and nothing is cached);
  `https` -> `https` redirects, including to another host, are still
  followed.
- **`mesh status`'s rendered table and `mesh admin list`'s table no longer
  interpret a device-reported name as Rich markup.** A name sourced from a
  third-party aggregator (loranet.pl/lorastats.pl) could embed markup like
  `[link=file:///etc/passwd]click[/link]`, which Rich rendered as a real,
  spoofed clickable terminal hyperlink -- every other console-print call
  site in this project already disabled markup interpretation for exactly
  this reason; these two direct `Console.print(table)` calls had not.
- **Fixed a critical authorization bypass: an admin public key already
  flagged as compromised by this project's own weak-key audit could be
  authorized onto a device with no warning, no dry-run line, and no log
  record.** This happened whenever `security.is_managed` was `false` --
  the default, and the path every ordinary `mesh provision` run takes,
  not an edge case -- because the weak-key audit on
  `template.admin_nodes` entries was enforced only inside the
  `security.is_managed=true` lockdown gate. An operator whose
  `known_bad_keys.txt` blocklist grew to cover an admin key already named
  in their template, or who provisioned before a compromise was known,
  could unknowingly keep writing that key to every newly provisioned
  device. Such keys are now excluded from the plan's desired admin-key
  set regardless of `is_managed`; each exclusion is reported as a
  `resolved_admin_key_rejected` plan warning naming the `Keys` sheet
  reference and the audit finding, visible in both the interactive
  confirmation prompt and `--dry-run --json`. A new
  `--allow-weak-admin-key` flag overrides this exclusion for an operator
  who deliberately wants to authorize a flagged key on an unlocked
  device -- it never overrides the separate `is_managed=true` lockdown
  refusal, which still hard-refuses the entire run if any admin key
  fails the audit. Two related behavior changes operators should be
  aware of: a template naming an admin ref that a blocklist update later
  flags no longer authorizes that ref by default; and, under
  `is_managed=true`, a fully-compromised `admin_nodes` list now correctly
  reports `weak_admin_key` (previously it would have -- after a naive fix
  -- misreported `no_admin_keys`), and a key that is both compromised and
  has a mismatched private counterpart now reports `weak_admin_key`
  rather than `private_key_mismatch`, since a compromised key is the more
  severe finding and the one that must be fixed regardless.
- `MESHPROVISION_LOCK_TIMEOUT` set to an unparseable, negative, or
  non-finite value now fails immediately with a clear error instead of
  silently falling back to the 5-second default -- matching how every
  other environment-driven numeric setting in this project already
  behaves. A previously-tolerated malformed value (for example, a typo'd
  unit suffix) will now need to be corrected; an empty or unset value is
  still treated as "use the default." Not enforced on platforms without
  `fcntl`, where the lock -- and therefore its timeout -- has no effect.

- The `security.is_managed` lockdown safety gate's "admin key has a
  private counterpart" check now cryptographically verifies that the
  private key actually corresponds to its claimed public key, instead of
  only checking that a row exists in the database. This closes a path
  where a hand-edited spreadsheet containing a mismatched key pair could
  lock a device (`--allow-lockdown`) with an admin key nobody could
  actually use to administer it, recoverable only by a physical factory
  reset. `mesh db verify` gained a matching `admin_key_mismatch` check.
- The database file and its backups are now written at permission mode
  `0600` (owner-only), matching the hardening already applied to the HTTP
  cache and backup directory, instead of inheriting the process umask.
- X25519 keypairs are generated with `cryptography`'s
  `X25519PrivateKey.generate()`, matching the CVE-2025-52464 advisory's own
  recommendation. Factory keys are treated as compromised and regenerated.
- Layered weak-key audit: structural checks (all-zero, small-order,
  repeated-byte, monotonic, low-entropy, unclamped), public/private consistency,
  a firmware-version window treating `[2.5.0, 2.6.11)` as presumptively
  compromised, cross-node duplicate detection, and a committed blocklist.
- `data/known_bad_keys.txt` contains the 7 verified X25519 small-order points
  from libsodium's blocklist and deliberately no invented entries: no public
  CVE-2025-52464 key list exists.
- Admin keys are inbound only, `admin_channel_enabled` is forced to `false`, and
  `security.is_managed` stays `false` unless a three-part safety gate and an
  explicit `--allow-lockdown` both pass. `is_managed=true` with zero authorized
  admin keys is refused outright.
- Key writes are verified by reading the public key back off the device
  (firmware issue #7449); an unconfirmed write leaves the database unchanged and
  exits non-zero.
- No raw cryptographic material is ever logged or printed: secrets are wrapped
  in `SecretBytes`, a structlog processor scrubs every event dict last, and
  tracebacks use a plain formatter rather than one that dumps locals.
- `MESHPROVISION_CONTACT` is required with no default, so nobody can
  unknowingly send dummy or third-party contact details to lorastats.pl.
- Secret hygiene is enforced by three independent layers: `.gitignore`, a
  `detect-secrets` pre-commit hook, and `tests/unit/test_no_tracked_secrets.py`.
- **Closed a case where a host-generated (non-factory) key could be
  treated as already-provisioned and left alone indefinitely instead of
  converging toward the template's desired state**, the round's original
  high-severity finding -- `host_generated` detection and its downstream
  convergence behavior are now covered end to end.
- `mesh provision --allow-weak-admin-key` and equivalent admin-key paths
  now hard-refuse an `ALL_ZERO`/`SMALL_ORDER` (small-subgroup) key
  outright; these two specific findings can no longer be overridden by
  any flag, since no legitimate key can ever have this shape.
- A node whose admin key is already relied on by another live,
  non-archived node ("admin-bearing") can no longer have that key
  silently rotated out from under the dependent node by `mesh adopt`,
  `mesh admin import --overwrite`, or `mesh admin bootstrap --ref`
  re-pointing an existing alias -- each now hard-refuses (or, for
  `bootstrap --ref`, clearly reports the collision) instead of only
  emitting a warning line.
- A node's private key material is now only ever recorded in the database
  when the corresponding public key has been read back and cryptographically
  proven to match it, closing a path where a database entry could claim a
  private key that doesn't actually pair with the device's real public key.
- `mesh provision`/`admin bootstrap` now verify the connected device's
  identity (its reported node id) against the database record before
  reconnecting to confirm a write, refusing to proceed if the device that
  answered isn't the one originally connected to -- guards against a
  swapped or renumbered device silently receiving a write meant for
  another node.
- A crash or kill between generating a new keypair and persisting it to
  the database previously risked losing the private key with no recovery
  path; a write-ahead pending-keypair file now lets an interrupted
  provision recover the key on the next run instead of orphaning it.
- `-vv`/`-vvv` verbose logging now withholds the raw secret arguments
  (admin keys, PSKs) that the `meshtastic` library itself logs at its own
  DEBUG level, instead of passing that library's log lines through
  unfiltered once verbosity was raised enough to unmute it.
- A malformed backup/profile YAML file's parse error no longer echoes the
  offending source line back to the terminal, which could otherwise leak
  a partially-typed secret value sitting on that line.
- Every place a device-reported or file-sourced string reaches a real
  terminal (node names, error messages built from untrusted input) is now
  passed through a control-character/bidi-override escaper before
  printing, closing a path where a maliciously crafted name could embed
  a terminal escape sequence (a clipboard write, a spoofed hyperlink, a
  cursor-repositioning sequence) that would otherwise reach the operator's
  real terminal verbatim.
- `atomic_write`/`lock_path_for` now resolve symlinks before comparing or
  locking paths, and the known-good safety copy's refresh now reads and
  validates the same bytes it just wrote (closing a read-after-write
  TOCTOU gap) rather than trusting a second, potentially-differing read.
- A crash partway through creating a new file (`mesh init`'s
  `write_new_file`, the known-good safety copy) can no longer leave a
  clobbered or partially-written file in its place; both now go through
  the same crash-safe `link_no_clobber` primitive.
- `mesh provision` never ran the documented cross-fleet "duplicate"
  (cloned-key) check: `audit_node_key` called `weakkeys.audit_node` with
  no `known_public_keys`, so a device presenting an exact clone of
  another node's keypair provisioned clean with zero warning -- the check
  only ever ran after the fact, via `mesh db verify`. A new
  `duplicate_candidate_keys` builds the comparison set (every other
  node's canonical `<hex>_pub` row, excluding this node's own ref, any
  `--ref` label alias, and any `mesh adopt`-minted `observed-*` ref) and
  is now passed into `audit_node_key` on every run. A clone now
  regenerates the node's key, or refuses outright (with a dedicated hint
  naming the matching ref(s) and the reported fingerprint) when the
  cloned material is itself an authorized admin key.
- `_finalize_admin_key_rotation_error`'s `"CVE-2025-52464" in exc.reason`
  substring check mis-caught the new duplicate-key refusal (whose own
  reason text also contains that substring) and gave it the generic
  "upgrade firmware" hint instead of the duplicate-specific one. Added a
  dedicated branch, checked before the generic one, keyed on the exact
  `weakkeys.DUPLICATE_KEY_REASON` value.
- `mesh adopt --from-backup`'s `resolve_node_id` key-match tier resolved a
  `Keys` sheet owner via the permissive `NodeId.try_parse`, which also
  accepts a 1-7 character all-hex string or an all-digit string -- shapes
  a short hex- or decimal-looking template `admin_nodes` label can
  satisfy by coincidence. A backup whose public key happened to match
  such a label's row could resolve to a bogus node id instead of failing
  closed. Now uses `schema.is_canonical_node_owner`'s round-trip check,
  same as `db/verify.py`; when the backup's key matches more than one
  distinct canonical owner (a cloned key), an explicit `--node-id`
  overrides the tier outright, otherwise it raises `NodeIdentityError`
  naming every matching owner, regardless of `--force`.
- The owner (name) write phase silently reset a device's `is_licensed`
  flag to `false` on every single run that touched it, including a run
  that only renamed the node. `iface.localNode.setOwner()` was called
  with no `is_licensed` argument, and the real `Node.setOwner()` defaults
  it to `False` -- and always applies that default whenever `long_name`
  is set, which this project's owner-phase write always does. An amateur
  radio operator's licensed status affects which LoRa regions/power
  levels are legally permitted, making this a correctness/compliance bug,
  not just cosmetic drift. `_run_name_phase` now always passes
  `is_licensed=plan.name_change.desired_is_licensed`, which echoes back
  whatever the device already reports (meshprovision has no template/CLI
  control over this field) instead of letting it fall to the library's
  default.
