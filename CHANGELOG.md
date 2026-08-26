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

### Security

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
