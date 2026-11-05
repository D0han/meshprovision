# Configuration

Part of the meshprovision docs — see the [README](../README.md).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `MESHPROVISION_DB_PATH` | `data/nodes_db.ods` | ODS node database (relative paths resolve against the CWD) |
| `MESHPROVISION_TEMPLATE_PATH` | `config/template.yaml` | Provisioning template |
| `MESHPROVISION_CACHE_DIR` | platformdirs user cache | HTTP TTL disk cache directory, also holding `lorastats_region_list.json` (lorastats.pl's region list), `lorastats_regions.json` (the region each node was last found in), `health/` (the 30-day history of `mesh health`, one file per node, at most 256 MiB), `network/` (`mesh network`'s 30 days of hourly region traffic, at most 256 MiB, with each region's `keys.json` key digests and `relays.json` learned relays) and `rate_limits.json` (hosts that answered HTTP 429, until their `Retry-After` ends). Safe to delete at any time while no `mesh` command is running; deleting `health/` or `network/` only loses that history. |
| `MESHPROVISION_CACHE_TTL` | `300` | Cache time-to-live, seconds. lorastats responses are reused for at least 60 s, even with `0` (unless `--no-cache`). |
| `MESHPROVISION_CONTACT` | (none — REQUIRED) | Your contact address, sent in the `User-Agent` to lorastats.pl |
| `MESHPROVISION_LORASTATS_REGIONS` | (none: the region list lorastats.pl's site navigation names, fetched at most weekly) | Comma-separated lorastats regions `mesh status` queries, in order (`--region` overrides it). Setting it means lorastats.pl's `/Nodes` page is never requested (see [Region list](commands.md#mesh-status)). Names are matched exactly, after Unicode NFC normalization: `Zachód` and `zachód` are different regions. At most 16; blank entries are ignored; a malformed name is rejected at startup. |
| `MESHPROVISION_LOG_LEVEL` | `WARNING` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |
| `MESHPROVISION_KNOWN_BAD_KEYS` | `data/known_bad_keys.txt` | Override path to the weak-key blocklist. Process environment only: a value in `.env` is ignored (with a warning). Not listed in the bundled `env.example`. |
| `MESHPROVISION_LOCK_TIMEOUT` | `60` | Seconds a write command polls the database write lock before giving up. Process environment only: a value in `.env` is ignored (with a warning). Not listed in the bundled `env.example`; mainly useful for scripting against a slow/contended database. A value that is not a finite, non-negative number is rejected with exit 2 rather than silently ignored. |

Precedence, highest to lowest: **CLI flag > environment variable > `.env`
file > built-in default** (`MESHPROVISION_KNOWN_BAD_KEYS` and
`MESHPROVISION_LOCK_TIMEOUT` are the exception: process environment
only). `.env` is found by searching upward from the
current working directory, or named explicitly with `--env-file`. The
upward search never crosses above your home directory (also when `$HOME`
is a symlink). It skips a `.env` owned by another user in a directory
that isn't private to you -- one you don't own, or that others can
create files in, such as `/tmp` -- since you can't tell who put it
there; run with `-v` to see which file was skipped and why. A symlinked `.env`
in such a directory that points at a file you own is still followed,
since its content is yours. Otherwise a discovered
`.env` (for a symlink, the file it points to) is refused unless it's a
regular file owned by you and not world-writable (group-writable is fine
when the group is your primary group and no one else is in it, the usual
`rw-rw-r--` default with a per-user group; a file writable by any other
group, or by a primary group shared with other users such as `users`, is
refused). On Linux the file's POSIX ACL counts too: an ACL entry that
lets another user or group write the file (for example one inherited from
a directory's default ACL) gets it refused, while read-only ACL entries
are fine. The error lists each problem with the `chmod` command that
fixes it (for an ACL, `chmod g-w`, which takes write access away from
every ACL entry at once). A `.env` owned by another user in your own
private directory is refused without suggesting `chown`: if you didn't
create it, don't use it -- delete it and keep your own. Pass `--env-file`
explicitly to bypass the search (and this check) entirely.

"No one else is in it" means the group lists no other members and no
other account has it as its primary group. On hosts whose LDAP/sssd
directory doesn't allow enumerating users, only local accounts can be
checked for the second part, so a directory user who shares your primary
group without being listed as a member can go unnoticed -- use
`chmod g-w .env` there if your primary group isn't private.

ACLs are only read on Linux, from the `system.posix_acl_access`
attribute. macOS ACLs and NFSv4 ACLs (`system.nfs4_acl`, e.g. on an
NFSv4 home directory) are not inspected, so there a discovered `.env`
can be writable by someone the check doesn't see -- keep such ACLs free
of write entries for others, or use `--env-file`.

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

Numeric fields are checked against the firmware's own field range when
the template loads (for example 0-4294967295 for the `*_secs`/`*_interval`
settings); an out-of-range value is a template error, never a
half-applied `mesh provision`. Two have a higher floor, because the
firmware raises a lower value itself and the write could never be
verified: `device.node_info_broadcast_secs` is at least 3600 and
`neighbor_info.update_interval` at least 14400. Likewise
`power.on_battery_shutdown_after_secs` is 0 (disabled) or at least 30.

On a default channel (the default key on the preset's own channel name,
as a stock LongFast node has) the firmware also raises some intervals,
at every boot: a telemetry interval below 1800 s (43200 s for `ROUTER`
and `ROUTER_LATE`) while any channel is a default one on the preset's
frequency slot (firmware 2.8; 2.7 checks no frequency slot at boot), and,
while the first channel that shares a position is a default one, `position_broadcast_secs` below 3600 s (43200 s for those
two roles) and `broadcast_smart_minimum_interval_secs` below 300 s. 0
means the firmware's default and is never raised. Such a value is still
written as given, since it holds on any other channel: the plan warns
(`interval_raised_at_boot`), the verify after the commit's reboot
accepts the raised value, and the next run plans no change for it. Read
in the firmware source (the position minimums since 2.7.18, the router
values since 2.7.21; older firmware raises only the telemetry intervals,
to 1800 s, and the verify accepts the template value too); not tried on
a device.

Changing `device.role` makes the firmware reset some settings to the new
role's defaults as it stores the role (`installRoleDefaults`): for
`ROUTER`, `rebroadcast_mode` becomes `CORE_PORTNUMS_ONLY`,
`is_unmessagable` true, and `gps_update_interval`,
`position_broadcast_secs`, the power section's `ls_secs`,
`min_wake_secs`, `sds_secs` and `wait_bluetooth_secs`, the display's
`screen_on_secs`, every telemetry interval, the neighbor info interval
and the paxcounter interval their defaults (power-saving builds also turn
`is_power_saving` on); for `CLIENT_HIDDEN`, `rebroadcast_mode` becomes
`LOCAL_ONLY` and the node info, position and neighbor info intervals and
the telemetry device, environment, air quality and health intervals the
firmware's "never" (2147483647 s); `ROUTER_LATE`, `SENSOR`, `TRACKER`,
`TAK`, `TAK_TRACKER` and `LOST_AND_FOUND` reset their own lists. The
plan names them (`role_defaults_rewrite`). Sections written after
`device` keep the template's values; for the template's
`is_unmessagable` (written before) and `rebroadcast_mode` and
`node_info_broadcast_secs` (written with the role) the verify accepts the
role's value on that run. Run `mesh provision` once more afterwards: with
the role in place, it sets the template's values wherever a default
replaced them.

A `CLIENT_HIDDEN` node never sends the periodic node info broadcast, so
other nodes may not learn its public key for a long time: direct messages
to it and remote admin of it can fail until they do. A template with that
role loads with a warning (`role_never_announces`).

Followed by module options:

```yaml
enabled_options: []
disabled_options: [mqtt, serial, range_test, store_forward, remote_hardware, paxcounter]
```

An option listed in *both* `enabled_options` and `disabled_options` is a
template-load error. An option meshprovision does not recognize is only a
warning, because firmware adds new modules over time; it is ignored (nothing
is written for it). So is an option whose module has no on/off switch in the
firmware (`telemetry`, `traffic_management`, `audio`, `ambient_lighting`): it
gets a load-time warning too, and `telemetry` is configured in its own
`telemetry:` section instead. `neighbor_info` must
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
from `name_suffix_alphabet`; write a literal brace as `{{`/`}}`. Names are
compared case-insensitively, so the alphabet's characters must be distinct
ignoring case (`"aA"` is a template-load error), and a character that
case-folds to several characters (`ß`, ligatures like `ﬁ`) is refused too.

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
warns at load time if either pattern yields fewer names than that (naming
the one that runs out first);
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

### Peers

```yaml
sync_peers: true
```

When `true` (the default), `mesh provision` ends by giving the device every other active
node of the database as a favorited contact, exactly what
`mesh peers --apply` does (it never unfavorites archived nodes) (see
[commands](commands.md)). A device only keeps the nodes it has heard recently and evicts the rest; a favorite is never
evicted, which matters most for routers and base stations. A node whose
public key is not in the Keys sheet cannot be added as a contact (it is only
favorited when the device already holds it under a key that passes the
weak-key audit); a node the device already holds under a *different* key,
and a node whose recorded key fails the weak-key audit or is shared with
another node, are reported and left alone. A failure in this step is a
warning, never a provisioning failure. Set `false` to leave the device's
contacts alone.

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
these blocks are left at the device's current value rather than reset,
except these, whose default is always applied: `device.role` (`CLIENT`),
`lora.region` (`EU_868`), `lora.use_preset` (`true`), `lora.modem_preset`
(`LONG_FAST`; an explicit `null` leaves it alone), `lora.hop_limit` (`3`),
`lora.tx_enabled` (`true`) and `lora.override_duty_cycle` (`false`).
[Every section field](#every-section-field) lists them all.

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
`is_managed: true` is lockdown mode; enabling it requires 1-3
`admin_nodes` **and** `--allow-lockdown` on the command line, plus the
safety gate described in [Security](security.md). `admin_channel_enabled`
must stay `false` — the legacy admin channel is never used anywhere in
this project. `packet_signature_policy` is firmware 2.8's XEdDSA
packet-signing policy control (`PACKET_SIGNATURE_POLICY_COMPATIBLE`,
`_BALANCED`, or `_STRICT`) — not in any official `meshtastic` release yet;
see the `meshtastic` dependency note in `CHANGELOG.md`. Omit it (or leave
it unset) to leave the device's current value untouched. What each value
does depends on the firmware. From 2.8.2: `COMPATIBLE` (the default) does
not sign and accepts unsigned packets; `BALANCED` signs broadcasts (and
NodeInfo/position even when unicast) and accepts unsigned packets, but an
unsigned NodeInfo cannot rename a node that has signed before; `STRICT`
signs like `BALANCED` and drops unsigned packets except PKI direct
messages, AES-CCM channels, acks/routing, traceroutes and key
verification, and also drops a signed packet from a sender whose key it
does not hold (other than a verifiable first-contact NodeInfo). On 2.8.0
and 2.8.1 every node signs broadcasts whatever the setting, and
`BALANCED` drops an unsigned broadcast from a node that has signed
before. Firmware before 2.8 is understood to strip signatures when
relaying (inferred from its schema, which has no signature field), so
`BALANCED`/`STRICT` are for meshes without such relays. It is only
written to a device reporting firmware 2.8 or newer: on older firmware (or
an unknown firmware version) a change is skipped with a plan warning,
since that firmware drops the field and the write could never be verified.

### Default channel

```yaml
default_channel:
  position_precision: 12
  is_muted: false
```

Scoped to the primary (index-0) channel only — meshprovision has no
secondary-channel provisioning story. `position_precision` is the GPS
position precision (in bits) shared in this channel's broadcasts; `0`
disables position sharing on the channel entirely, and 32 shares it
exactly. Firmware 2.8 keeps at most 15 bits (about 700 m) on a channel
anyone can decrypt (no key, a 1-byte key, or the default key's family, as
on a stock LongFast primary): a higher value is written as given, the plan
warns (`position_precision_capped`), and the verify accepts 15. Firmware
2.7 keeps the value. `is_muted` mutes the channel's traffic (received but
not relayed/notified).

Unlike every other block above, this one is **not** part of
`config`/`module_config`: a device's channels live in a separate
protobuf container and are written through a different device mechanism
(a channel write, not a config write). It applies without a reboot (read
in the firmware source at 2.7.26 and 2.8.3, not tried on a device), which
`mesh provision --dry-run` states in a warning whenever this section would
be written.

If the device reports no primary channel, or reports it as disabled,
`default_channel` is left out of the plan with a
`primary_channel_unavailable` warning (shown by `--dry-run` and in the
`--json` plan): a channel write sends the whole channel, so it would
replace the device's channel with a near-empty one. Everything else,
including `security`, is still applied and the node is recorded; the
warning repeats on every run until the primary channel is enabled or
`default_channel` is removed from the template.

### Every section field

Each section block takes the fields below and nothing else (an unknown
field is a template error). A field left out is left at the device's
current value, except where a default is given. Seconds fields and other
counts take a whole number from 0 up to the firmware field's own maximum
unless a range is given.

#### `device`

| Field | Value | Meaning |
|---|---|---|
| `role` | role name, default `CLIENT`; not `ROUTER_CLIENT`, and `REPEATER` only on firmware before 2.7.11 (later firmware stores `CLIENT` in their place, and turns `store_forward.is_server` on when store and forward is enabled; `mesh provision` refuses to write it) | Device role |
| `rebroadcast_mode` | rebroadcast mode name; not `NONE` with role `ROUTER`, `ROUTER_LATE` or `REPEATER` (the firmware relays `ALL` for them; for `ROUTER_LATE` from firmware 2.7.20), and `KNOWN_ONLY` only on firmware before 2.8.0 (later firmware then ignores every admin message from the connected client, so the node could no longer be configured over USB, BLE or TCP; `mesh provision` refuses to write it, and warns on older firmware) | Which packets the node relays |
| `node_info_broadcast_secs` | seconds, at least 3600 | Node info broadcast interval |
| `button_gpio` | GPIO number | User button pin override |
| `buzzer_gpio` | GPIO number | Buzzer pin override |
| `double_tap_as_button_press` | `true`/`false` | An accelerometer double tap counts as a button press |
| `disable_triple_click` | `true`/`false` | Disables the triple-click gesture |
| `led_heartbeat_disabled` | `true`/`false` | Disables the heartbeat LED |
| `tzdef` | POSIX TZ string | Time zone |

#### `lora`

| Field | Value | Meaning |
|---|---|---|
| `region` | region name, default `EU_868`; not `UNSET` (the firmware switches the transmitter off) | LoRa region |
| `use_preset` | `true`/`false`, default `true`; `false` only on a node that already holds its own bandwidth, spread factor and coding rate (set them in the Meshtastic app): the template cannot set them, so `mesh provision` refuses to switch off the preset of a node that holds 0 for any of them | `modem_preset` sets the radio parameters |
| `modem_preset` | preset name, default `LONG_FAST` | Modem preset; `null` leaves it alone |
| `hop_limit` | 0-7, default 3 | Maximum hop count |
| `tx_enabled` | `true`/`false`, default `true` | The radio may transmit |
| `tx_power` | 0-30 dBm | Transmit power; 0 means the region's limit. The firmware holds at most that limit (27 dBm for `EU_868`) unless the owner is licensed, also when a region change lowers it, so a higher value (or 0) gets a plan warning (`tx_power_limited_by_region`) and the verify accepts the limit |
| `channel_num` | channel number | LoRa channel override |
| `frequency_offset` | Hz | Frequency offset |
| `override_duty_cycle` | `true`/`false`, default `false` | Overrides the regional duty-cycle limit |
| `sx126x_rx_boosted_gain` | `true`/`false` | SX126x boosted receive gain |
| `ignore_mqtt` | `true`/`false` | Ignores packets that came from MQTT; a region change sets it to `true` when the new region has a duty-cycle limit, so `false` takes a second run (the plan warns: `region_change_sets_ignore_mqtt`) |
| `config_ok_to_mqtt` | `true`/`false` | Consents to this node's traffic being uplinked to MQTT |

#### `position`

| Field | Value | Meaning |
|---|---|---|
| `position_broadcast_secs` | seconds | Position broadcast interval |
| `position_broadcast_smart_enabled` | `true`/`false` | Smart (distance and time gated) broadcasts |
| `fixed_position` | `true`/`false` | The position is fixed, not from GPS; left out, a position fixed with `--setlat` stays fixed |
| `gps_update_interval` | seconds | GPS fix interval |
| `position_flags` | bit mask | Which fields a position broadcast carries |
| `broadcast_smart_minimum_distance` | meters | Movement before a smart broadcast |
| `broadcast_smart_minimum_interval_secs` | seconds | Minimum time between smart broadcasts |
| `gps_mode` | GPS mode name | GPS enabled, disabled or not present |

#### `power`

| Field | Value | Meaning |
|---|---|---|
| `is_power_saving` | `true`/`false` | Sleeps between radio activity |
| `on_battery_shutdown_after_secs` | seconds, 0 or at least 30 | Shutdown after this long on battery; 0 disables |
| `adc_multiplier_override` | number | Battery voltage ADC multiplier |
| `wait_bluetooth_secs` | seconds | Bluetooth stays on this long after boot |
| `sds_secs` | seconds | Super-deep-sleep duration |
| `ls_secs` | seconds | Light-sleep duration |
| `min_wake_secs` | seconds | Minimum time awake after a wake event |

#### `telemetry`

| Field | Value | Meaning |
|---|---|---|
| `device_telemetry_enabled` | `true`/`false` | Device metrics are collected |
| `device_update_interval` | seconds | Device metrics interval |
| `environment_measurement_enabled` | `true`/`false` | An environment sensor is read |
| `environment_update_interval` | seconds | Environment telemetry interval |
| `environment_screen_enabled` | `true`/`false` | Environment readings on the screen |
| `environment_display_fahrenheit` | `true`/`false` | The screen shows Fahrenheit |
| `air_quality_enabled` | `true`/`false` | An air quality sensor is read |
| `air_quality_interval` | seconds | Air quality telemetry interval |
| `air_quality_screen_enabled` | `true`/`false` | Air quality readings on the screen |
| `power_measurement_enabled` | `true`/`false` | A power sensor is read |
| `power_update_interval` | seconds | Power telemetry interval |
| `power_screen_enabled` | `true`/`false` | Power readings on the screen |
| `health_measurement_enabled` | `true`/`false` | A health sensor is read |
| `health_update_interval` | seconds | Health telemetry interval |
| `health_screen_enabled` | `true`/`false` | Health readings on the screen |

#### `neighbor_info`

| Field | Value | Meaning |
|---|---|---|
| `enabled` | `true`/`false` | The neighbor info module runs |
| `update_interval` | seconds, at least 14400 | Neighbor info broadcast interval |
| `transmit_over_lora` | `true`/`false` | Neighbor info is sent over LoRa |

#### `default_channel`

| Field | Value | Meaning |
|---|---|---|
| `position_precision` | bits, 0-32 | Position precision shared on the primary channel; 0 shares none, 32 is exact; at most 15 is kept on a channel anyone can decrypt (firmware 2.8) |
| `is_muted` | `true`/`false` | The primary channel is muted |

#### `security`

| Field | Value | Meaning |
|---|---|---|
| `is_managed` | `true`/`false`, default `false` | Lockdown mode (see [Security block](#security-block)) |
| `admin_channel_enabled` | `false`, the default | The legacy admin channel; must stay off |
| `serial_enabled` | `true`/`false` | The serial console and API; `false` is refused over a serial connection (see [`mesh provision`](commands.md#mesh-provision)) |
| `debug_log_api_enabled` | `true`/`false` | Debug logging over the API |
| `packet_signature_policy` | policy name | Firmware 2.8 packet signing (see [Security block](#security-block)) |
