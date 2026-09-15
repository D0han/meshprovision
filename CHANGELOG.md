# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Single `mesh` console script (distribution `meshprovision`) with five
  subcommand groups: `provision`, `status`, `admin`, `db`, and `adopt`.
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
- `mesh adopt`: strictly read-only inventory of an already-configured,
  already-deployed node -- connects like `mesh provision` but never writes
  to the device, and records live names, admin keys, firmware version,
  region, role, and BLE PIN as a new `management=observed` node. A new
  `management` column on the `Nodes` sheet (`template`/`observed`, default
  `template`) gates `mesh provision`/`mesh admin bootstrap`: touching an
  observed node now requires an explicit `--enroll`, checked before any
  admin-key resolution and before `--dry-run`'s early return. Unregistered
  admin keys are reported by fingerprint only by default; `--show-admin-keys`
  is the one deliberate exception, printing paste-ready `mesh admin import`
  commands. Re-adopting fully replaces `authorized_admin_keys` with current
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
- README covering installation, the template and `.ods` walkthroughs, every
  command, the security model, and Linux Mint troubleshooting.

### Fixed

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

### Security

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
