# Configuration

Part of the meshprovision docs — see the [README](../README.md).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `MESHPROVISION_DB_PATH` | `data/nodes_db.ods` | ODS node database (relative paths resolve against the CWD) |
| `MESHPROVISION_TEMPLATE_PATH` | `config/template.yaml` | Provisioning template |
| `MESHPROVISION_CACHE_DIR` | platformdirs user cache | HTTP TTL disk cache directory. Safe to delete at any time while no `mesh` command is running. |
| `MESHPROVISION_CACHE_TTL` | `300` | Cache time-to-live, seconds |
| `MESHPROVISION_CONTACT` | (none — REQUIRED) | Your contact address, sent in the `User-Agent` to lorastats.pl |
| `MESHPROVISION_LOG_LEVEL` | `WARNING` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `MESHPROVISION_KNOWN_BAD_KEYS` | `data/known_bad_keys.txt` | Override path to the weak-key blocklist. Read directly by the crypto layer; not listed in the bundled `env.example`. |
| `MESHPROVISION_LOCK_TIMEOUT` | `5.0` | Seconds a write command polls the database write lock before giving up. Not listed in the bundled `env.example`; mainly useful for scripting against a slow/contended database. A value that is not a finite, non-negative number is rejected with exit 2 rather than silently ignored. |

Precedence, highest to lowest: **CLI flag > environment variable > `.env`
file > built-in default**. `.env` is found by searching upward from the
current working directory, or named explicitly with `--env-file`. The
upward search never crosses above your home directory, and a discovered
`.env` is refused unless it's owned by you and not world-writable
(group-writable is fine when the group is your primary group, the usual
`rw-rw-r--` default; a file writable by any other group is refused) -- pass `--env-file` explicitly to bypass the search
(and this check) entirely.

`MESHPROVISION_CONTACT` has no default because lorastats.pl requires
identifiable contact information in every request and bans IP addresses
that send missing, dummy, or third-party contact details — a default
would make someone else wear your traffic.

## Template walkthrough (`config/template.yaml`)

The bundled `src/meshprovision/examples/template.example.yaml` (`mesh
init`'s source for `config/template.yaml`) starts with:

```yaml
version: 1
```

Followed by module options:

```yaml
enabled_options: [telemetry]
disabled_options: [mqtt, serial, range_test, store_forward, remote_hardware, paxcounter]
```

An option listed in *both* `enabled_options` and `disabled_options` is a
template-load error. An option meshprovision does not recognize is only a
warning, because firmware adds new modules over time. `neighbor_info` must
not appear in either list — unlike `telemetry`, it has a real device-level
`enabled` field, so it gets its own dedicated `neighbor_info:` block instead
(see below); listing it here is also a template-load error.

### Naming

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
version a given device runs). These are byte limits, not character
limits — one accented or non-Latin character can consume the entire
4-byte `short_name` budget on its own.

**Capacity** is `alphabet_size ** suffix_slots`. `MT{n}{n}` over the
base36 alphabet above is `36 ** 2 = 1296` names. `name_min_capacity: 100`
warns at load time if the pattern yields fewer names than that;
`name_capacity_strict: true` turns that warning into a hard load error;
`name_capacity_warn_utilization: 0.9` warns on every run once 90% of the
namespace is in use; exhaustion of the namespace is a clear error naming
the offending pattern.

```yaml
is_unmessagable: false
```

An owner-identity field, sent through the same admin message as the names
above (`Node.setOwner`'s `User.is_unmessagable`). `true` marks the node
"infrastructure" -- a sensor or repeater that should never show up as a
target for direct messages. Omitted or `null` (the default) leaves the
device's current value untouched; there is no CLI override, unlike
`short_name`/`long_name`.

### Admin nodes

```yaml
admin_nodes: []
```

0 to 3 entries, 3 being the firmware's `config.security.admin_key`
capacity. Each entry is a **label**, not a key, and must resolve to a
`<ref>_pub` row in the `Keys` sheet at provisioning time. meshprovision
appends `_pub`/`_priv`/`_psk` itself, so a ref must not already end in one
of those, and `observed-` is reserved for the synthetic refs `mesh
adopt` mints on its own — see [the database docs](database.md#observed--rows). An
unresolvable ref is an error naming the ref and pointing at
`mesh admin bootstrap` / `mesh admin import`. Zero admins is a legitimate,
deliberate configuration and is never "repaired" toward three.

`device` (role: `CLIENT`), `lora`, `position`, `power`, `default_channel`,
`telemetry`, and `neighbor_info` blocks follow. Fields omitted from any of
these blocks are left at the device's current value rather than reset.

### Region: `EU_868`, not `PL`

```yaml
lora:
  region: EU_868
```

There is no "PL" region code in the Meshtastic protobuf, despite the
country code — `EU_868` is the region used across Poland and most of the
EU. Do not confuse this with the lorastats `--region PL` path segment
used by `mesh status`, which is a completely different namespace: one is
a Meshtastic `RegionCode` protobuf value, the other is a URL path segment
on lorastats.pl. They are unrelated and both correct in their own
context — this is a real trip hazard.

### Security block

```yaml
security:
  is_managed: false
  admin_channel_enabled: false
  packet_signature_policy: PACKET_SIGNATURE_POLICY_COMPATIBLE
```

Key material **never** goes in this file — a template containing
`private_key`, `public_key`, or `admin_key` is refused outright.
`is_managed: false` is lockdown mode; enabling it requires 1-3
`admin_nodes` **and** `--allow-lockdown` on the command line, plus the
safety gate described in [Security](security.md). `admin_channel_enabled`
must stay `false` — the legacy admin channel is never used anywhere in
this project. `packet_signature_policy` is firmware 2.8's XEdDSA
packet-signing policy control (`PACKET_SIGNATURE_POLICY_COMPATIBLE`,
`_BALANCED`, or `_STRICT`) — not in any official `meshtastic` release yet;
see the `meshtastic` dependency note in `CHANGELOG.md`. Omit it (or leave
it unset) to leave the device's current value untouched.

### Default channel

```yaml
default_channel:
  position_precision: 12
  is_muted: false
```

Scoped to the primary (index-0) channel only — meshprovision has no
secondary-channel provisioning story. `position_precision` is the GPS
position precision (in bits) shared in this channel's broadcasts; `0`
disables position sharing on the channel entirely. `is_muted` mutes the
channel's traffic (received but not relayed/notified).

Unlike every other block above, this one is **not** part of
`config`/`module_config`: a device's channels live in a separate
protobuf container and are written through a different device mechanism
(a channel write, not a config write). Its reboot behavior has not been
verified against real firmware, so `mesh provision --dry-run` surfaces an
explicit warning whenever this section would be written.
