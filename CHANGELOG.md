# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Single `mesh` console script (distribution `meshprovision`) with four
  subcommand groups: `provision`, `status`, `admin`, and `db`.
- `mesh provision`: Serial/BLE/TCP transports with an explicit selection
  priority, FACTORY/PROVISIONED/FOREIGN detection, a pure change planner that
  makes `--dry-run` exact, drift repair, and transactional writes verified by
  read-back.
- `mesh status`: strictly read-only health reporting, merging loranet.pl's bulk
  `nodes.json` dump with per-node lorastats.pl queries; `rich` table and
  `--json` output, `--watch`, and configurable online/stale/offline thresholds.
- `mesh admin bootstrap | import | list`: admin-key custody for 0-3 inbound
  admin nodes, including pending cross-authorization reporting.
- `mesh db verify | backup`: schema, cross-reference and weak-key verification,
  plus timestamped backups with retention.
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

### Security

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
