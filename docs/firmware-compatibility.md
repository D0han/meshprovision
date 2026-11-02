# Firmware 2.8 and beyond

Part of the meshprovision docs — see the [README](../README.md).

Firmware 2.8 ([release notes](https://github.com/meshtastic/firmware/releases/tag/v2.8.0.47db0e3))
makes several changes worth tracking here. This is a living record of
what's known, what's already fixed, and what's deliberately not guessed
at.

**The `meshtastic` library is pinned to a commit, not a release.** The
newest PyPI release when this was checked (2026-11-02), 2.7.11, has no
firmware 2.8 protobuf fields, so `pyproject.toml` pins `meshtastic` to
commit `0a18357` of `meshtastic/python`'s unreleased `master` branch
(protobufs v2.8.1). That commit carries the 2.8 schema:
`security.packet_signature_policy` (XEdDSA packet signing, a template
field), the `TINY_FAST`/`TINY_SLOW`/`MEDIUM_TURBO` modem presets and the
new amateur-band regions. The v2.8.1 schema adds four hardware models
(`T_CONNECT_PRO`, `AXIOMETA_GENESIS_MINI`, `MAKERFABS_NOMAD_TERMINAL`,
`THINKNODE_MX`), which meshprovision now names like any other; their
chipset shows as unknown. meshprovision reads its region/role/hardware
tables from the *installed* library's enums (`enums.py`), so these need no
code of their own. Once a 2.8-compatible
release lands on PyPI, the pin goes back to a normal version constraint
(after the full test suite, which catches silent enum renames such as
`SENSELORA_RP2040` -> `MAKERFABS_TRACKER`).

**Fixed already:** `long_name`'s enforced limit dropped from 39 to 25
UTF-8 bytes. This needed no protobuf change — it's a validation constant
in this project, not a device-reported field — so `LONG_NAME_MAX_BYTES`
is now 25 regardless of which firmware a given device runs. A name that
fits in 25 bytes always fit in the old 39-byte limit too, so this is a
pure tightening, not a behavior change for anyone still on 2.7.x.

**Informational, no code change needed:** new US nodes now default to the
`LongTurbo` modem preset instead of `LongFast`, and the two presets
cannot hear each other. meshprovision has no opinion on modem preset
defaults — it applies whatever `lora.modem_preset` your template
specifies — but if you're provisioning new nodes onto an existing US
mesh, check your template names the preset your mesh actually uses
rather than relying on the device's own factory default.

**Informational: `lora.coding_rate` with a preset.** Verified in the
firmware source at v2.8.2 (`RadioInterface.cpp`): a `coding_rate` of 5-8
that is higher than the preset's raises the preset's coding rate even
with `use_preset` on (nodes on the same preset still hear each other, at
more airtime per packet). The 2.8.1 protobuf documentation says this holds
since firmware 2.7.18 (unverified). meshprovision does not
set or read `coding_rate`, so a value set earlier in the app survives
`mesh provision`; reset it to 0 in the app if a node should use the
preset's own rate.

## Node identity: the node id follows the key

Firmware 2.8 derives a node's id from its public key. This changes what
"the same node" means for anything keyed by node id, the database
included. What is known, and how sure:

**Verified** means read in the firmware source at tags `v2.8.0.47db0e3`
and `v2.8.1.8e6a88d` (and `develop` as of 2026-10-31); **unverified**
means inferred, not read end to end. **Nothing here was tried on a
device.**

- *Verified:* `NodeDB::createNewIdentity()` sets the node number to the
  CRC-32 of the public key whenever that differs from the current
  number, and deletes the old self entry. It does not check the result
  against reserved numbers (below 4) or the broadcast address, which the
  firmware's own random pick avoids. Firmware 2.7.26 has no such code.
- *Verified:* it runs after every successful key generation or
  derivation, and the key is derived from the stored private key at
  every boot. So a node that already has a key and is upgraded from 2.7
  comes back under a new id on its first 2.8 boot, without any
  provisioning.
- *Verified:* an admin `set_config.security` carrying both keys (what
  `mesh provision` sends) stores them and reboots the node; the new id
  appears at that reboot. A FACTORY node always gets a new key, and
  `--force-regenerate-key` writes one, so both end under a new id.
- *Verified:* key generation waits while the LoRa region is `UNSET`.
  The moment a region is first set, an unlicensed node mints its key and
  takes the derived id at once, without a reboot. One that already holds
  a private key only re-derives its public key from it then, so its id
  changes only if it is not already that key's derived id.
- *Verified:* `set_owner` regenerates the key only when `is_licensed`
  toggles; `mesh provision` always writes back the device's own value, so
  its name writes never renumber a node.
- *Unverified:* the CRC is zlib's CRC-32 (`zlib.crc32` of the 32 raw key
  bytes). The firmware's CRC function itself was not read; zlib's matches
  the id of 27 of 307 keyed nodes of one real region, which chance would
  not produce.
- *Unverified:* what happens to admin messages still being sent after a
  renumber in the middle of a session (the library addresses local admin
  messages to the number it last heard; 2.8.0 does not tell connected
  clients about the new number).

What meshprovision does about it:

- **A key write follows the node.** After `mesh provision` writes a new
  node key, its final verify accepts a new id only when it is exactly the
  one derived from the key it wrote and the device holds that run's
  private key; it then moves the database row (or records a first
  provisioning) under the new id. Any other id is still refused as a
  possible device swap. The plan warns beforehand
  ([`mesh provision`](commands.md#mesh-provision)).
- **A fresh key never derives a used id.** A key whose derived id is
  reserved, the broadcast address, or another database row's is drawn
  again.
- **A renumbered node is recognised, not adopted as a stranger.** A node
  met under an id with no row, whose key is one row's (or whose pending
  keypair from an interrupted run it holds), is refused with the exact
  [`mesh db renumber OLD NEW`](commands.md#mesh-db) command to run first.
  [`mesh network keys`](commands.md#mesh-network-keys) reports such a move
  as a `migration` when the old id was heard (in the 30 days stored)
  before the new one; when it was not heard at all, the move looks exactly
  like a clone and stays critical, naming that command.
- **A first region set is refused.** `mesh provision` refuses a plan
  that would set the LoRa region of a 2.8 device whose region is still
  `UNSET`, before writing anything: set the region first (Meshtastic app,
  or `meshtastic --set lora.region <R>`), reconnect, and run it again.
  Not refused: an unlicensed device already on the id derived from the
  key pair it holds, when the plan writes no new key (it keeps that id).
  Licensed nodes take another path in the firmware at that moment, not
  traced; they are refused too. Older or unparseable firmware versions
  are not refused.
- `mesh health` history stays filed under the old id.

**Resolved — the anti-spoofing check does not block a key rotation.**
Firmware 2.8 refuses to update a NodeDB entry when a received `NodeInfo`
reports a public key that doesn't match the one on file for that node
number (see
[`meshtastic/firmware` discussion #5007](https://github.com/meshtastic/firmware/discussions/5007)).
That check lives in `NodeDB::updateUser()` (read in the firmware source,
2026-10-02) and only fires on packets received over the mesh, not on the
admin `set_config` path `--force-regenerate-key` uses, so the local write
is unaffected. On 2.8 the rotated key also brings a new node id, so peers
meet it under a number they have no key for. How peers treat the entry
they cached for the old number was not verified; it is a mesh-wide
effect meshprovision cannot see or control from one connection.

**The same node-identity-trust concern, in a different shape:**
`mesh adopt --from-backup` (see [`mesh adopt`](commands.md#mesh-adopt))
records a node from an exported Meshtastic app config backup instead of
a live connection, and a backup file never asserts its own node id with
any authority a live device's handshake would. That command refuses to
guess: it requires an explicit `--node-id`, a `Keys` sheet public-key
match, or a paired node-db export's `myNodeNum` before writing anything,
and a bare long-name match is offered only as a hint, never used to
adopt. This is the same class of spoofing concern as the anti-spoofing
check above — an attacker-crafted backup naming someone else's node id
is exactly what that resolution order exists to make hard to do by
accident.
