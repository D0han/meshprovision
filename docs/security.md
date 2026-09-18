# Security

Part of the meshprovision docs — see the [README](../README.md). See also
[Firmware 2.8 and beyond](firmware-compatibility.md) for a related,
still-open risk.

## Key generation

`X25519PrivateKey.generate()` from `cryptography` — exactly what the CVE
advisory itself recommends (`openssl genpkey -algorithm x25519 -outform
DER | tail -c32`). 32 raw bytes private + 32 public, stored base64 in the
`Keys` sheet, matching the `base64:` convention the Meshtastic CLI uses in
its own export format. Factory keys are treated as compromised and
regenerated.

## Write verification

Every config write is re-read and compared to intent; key writes are
verified by reading the public key back off the device (firmware issue
#7449). An unconfirmed write leaves the ODS untouched and exits non-zero.

## The admin-key model

Inbound only. The template's `admin_nodes` public keys are resolved from
the `Keys` sheet and written into the target's `config.security.admin_key`
(Python API: `security.adminKey`) — a `repeated bytes` field, capacity 3.

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
admin keys is refused outright — that combination locks the node with
nobody able to administer it.

## CVE-2025-52464 and the weak-key audit

**"Repeated Public/Private Keypairs"**, CVSS 9.5, affects firmware
`>= 2.5.0` and `< 2.6.11`. Two root causes — vendor mass-flashing cloned
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

It does **not** contain the keypairs affected by CVE-2025-52464 — **no
such list has ever been published.** This was verified during planning by
enumerating the complete file trees of `meshtastic/firmware` and
`meshtastic/Meshtastic-Android` and reading `NodeDB.cpp` and
`CryptoEngine.cpp` at tag `v2.6.12.9861e82`: the firmware's only duplicate
detection is the on-mesh advertisement check in `NodeDB.cpp` ("Remote
device has advertised your public key"), and the advisory itself
publishes no blocklist. The "compares against a hash of known duplicates"
claim in secondary reporting corresponds to nothing in the source.
Publishing such a list would also mean publishing live private keys for
nodes still in the field.

What **is** in it: the 7 canonical X25519 small-order/degenerate public
points from libsodium's `has_small_order()` blocklist in
`crypto_scalarmult/curve25519/ref10/x25519_ref10.c` — the all-zero point,
`0x01`-then-zeros, the two order-8 points, and `p-1`/`p`/`p+1`
(`p = 2**255-19`). Each carries a provenance comment, so the file is
auditable rather than a magic list. The same 7 values are also compiled
into `crypto/weakkeys.py:SMALL_ORDER_POINTS`, so they still apply if the
file is absent. The file was deliberately **not** padded with invented
entries — a padded blocklist gives false assurance, which is worse than
an honest short one.

Your effective controls against CVE-2025-52464 are therefore the
firmware-version window check and cross-node duplicate detection across
your own `Keys` sheet — **not** this file.

Format and extension path: base64, one key per line, `#` comments. If the
community ever publishes a real list, merge it with no code change:

```bash
python scripts/update_known_bad_keys.py --source new_keys.txt --comment "provenance"
```

(also supports `--dry-run` and `--check`). Public keys only — never feed
it private key material. Override the file's location with
`MESHPROVISION_KNOWN_BAD_KEYS`.

## Secret hygiene

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
- `mesh adopt --from-backup`'s report follows the same rule as a
  live-device adopt: the node's own keypair and any decoded channel PSK
  are never rendered raw, in human or `--json` output — only fingerprints
  and a weak-key-audit summary (see [`mesh adopt`](commands.md#mesh-adopt)).
  The **input file itself** is a different matter — see the table below.

## Sensitive vs example files

| Path | Tracked in git? | What it is |
|---|---|---|
| `src/meshprovision/examples/env.example` | tracked, ships in every install | Variable names only, no values. `MESHPROVISION_CONTACT` ships empty. `mesh init`'s source for `.env`. |
| `.env`, `.env.*` | IGNORED | Your real environment, including your contact address |
| `src/meshprovision/examples/template.example.yaml` | tracked, ships in every install | Example template, generic `MT{n}{n}` naming. `mesh init`'s source for `config/template.yaml`. |
| `config/template.yaml` | IGNORED | Your operational template |
| `data/nodes_db.example.ods` | tracked | Fake nodes, ASCII placeholder "keys" |
| `data/nodes_db.ods` | IGNORED | Your real database — contains live private keys and BLE PINs |
| `data/backups/` | IGNORED (except `.gitkeep`) | Timestamped database backups, plus the single `nodes_db.known-good.ods` safety copy (same directory, same `0700`/`0600` treatment, same ignore rule — see [Recovering from a bad hand-edit](database.md#recovering-from-a-bad-hand-edit)) |
| `data/known_bad_keys.txt` | tracked | Public small-order X25519 points; no private material |
| `.cache/` and the platform cache dir | IGNORED | HTTP TTL response cache |
| A Meshtastic app `.cfg`/`.yaml`/node-db `.json` backup (for `mesh adopt --from-backup`) | never tracked; not covered by `.gitignore` since it can live anywhere | A `.cfg`/`.yaml` profile carries the node's **private key** and, when set, a channel PSK, both in clear — treat it exactly like `data/nodes_db.ods`. Keep it outside the repo, or under a path your own `.gitignore` already excludes |
| `*.key`, `*.pem`, `secrets/`, `*.log`, `logs/`, `*.ods.bak` | IGNORED | Never commit |

This is enforced by three independent layers: (1) `.gitignore`, (2) the
`detect-secrets` pre-commit hook, and (3)
`tests/unit/test_no_tracked_secrets.py`, which shells out to
`git ls-files` and fails CI if any sensitive pattern is ever tracked,
catching `git add -f` bypasses that `.gitignore` alone would miss.
