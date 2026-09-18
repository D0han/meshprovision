# Firmware 2.8 and beyond

Part of the meshprovision docs — see the [README](../README.md).

Firmware 2.8 ([release notes](https://github.com/meshtastic/firmware/releases/tag/v2.8.0.47db0e3))
makes several changes worth tracking here. As of this writing, the
`meshtastic` Python library this project depends on is still at
**2.7.11 on PyPI** — the same version pinned in `pyproject.toml` — so
anything that needs a newer protobuf schema than 2.7.x defines is **not
yet something meshprovision can read or write**, regardless of what
changes here. This is a living record of what's known, what's already
fixed, and what's deliberately not guessed at.

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

**Blocked pending a `meshtastic` library update:** new LoRa regions
(70cm/1.25m/2m amateur bands, EU region consolidation), new modem presets
(`TinyFast`/`TinySlow`), XEdDSA packet-signing configuration, and the
licensed-operator rebroadcast restriction are all new or changed protobuf
fields the currently-pinned library has no definitions for.
meshprovision reads region/role/hw_model from whatever enum tables the
*installed* `meshtastic` package's protobufs expose (`enums.py`), so once
a 2.8-compatible release lands on PyPI and the dependency floor is
raised, these should mostly appear automatically — but that's untested
until such a release exists, and this project's practice (see
[CVE-2025-52464](security.md#cve-2025-52464-and-the-weak-key-audit)) is
to verify against real source or a real device before claiming
compatibility, not assume it.

**Found during research, not yet acted on — a real risk to the weak-key
remediation workflow:** firmware 2.8 derives a node's number from its
public key rather than its MAC address, specifically to stop an attacker
spoofing a User packet from an existing node number with a new public
key, and it refuses to update a NodeDB entry when a received `NodeInfo`
reports a public key that doesn't match what's already on file for that
node number (see
[`meshtastic/firmware` discussion #5007](https://github.com/meshtastic/firmware/discussions/5007)).
That's backwards compatible for already-provisioned nodes — but this
project's `--force-regenerate-key` workflow does exactly what the
anti-spoofing check is designed to catch: it legitimately rotates a
node's own public key in place, under the same node number, when the
weak-key audit flags it as compromised. If other mesh peers already have
that node cached with its old (compromised) key, this firmware behavior
may make them refuse the new key on the next broadcast — potentially
leaving peers trusting a key you've just revoked until they're
individually made to forget and re-learn it. This is a mesh-wide security
property meshprovision cannot see or control from a single provisioning
connection, and it has not been verified against a real 2.8 device or an
updated library. It's recorded here as a known, unresolved risk to
revisit once real 2.8 tooling exists.
