# Deliberate deviations from the original specification

Part of the meshprovision docs — see the [README](../README.md).

Each of these was confirmed with the project owner during planning and is
documented here rather than buried.

1. **`security.adminKey`, not `adminKeyAuthorized`.** The admin-key
   protobuf field is `config.security.admin_key` (`repeated bytes`, field
   3), exposed by the Python API camelCase as `adminKey`. There is no
   `adminKeyAuthorized` field. `SecurityConfig` also carries
   `admin_channel_enabled` (field 8) and `is_managed` (field 4).
2. **The region list is static and config-overridable, never
   auto-discovered.** No JSON endpoint for it exists —
   `/API/Regions/JSON` returns the HTML API page and `/Regions` is an
   HTML map. Discovering regions would require scraping, which
   lorastats.pl explicitly forbids and bans IP addresses for. Default:
   `["PL"]`.
3. **lorastats is queried per node via `?node=<hex>`, not by bulk region
   dump.** `?node=` is a server-side filter that turns a 1.8 MB region
   dump into a ~150 byte response. Related hardening: the region path
   segment is **not** validated server-side
   (`/API/NotARealRegion123/Nodes/JSON` returns the same data with HTTP
   200), and invalid paths elsewhere also return HTML with HTTP 200 — so
   the datasource asserts the body actually parses as JSON and never
   trusts the status code.
4. **`odfpy` directly, not `pandas`.** pandas type-coerces cells, and a
   hex node id like `1234567e8` is silently parsed as a float in
   scientific notation, corrupting the primary key. Every cell is read
   and written as an explicit string. It also avoids a ~50 MB dependency
   for a sheet holding a few dozen rows.
5. **The `[ble]` extra is a documented alias**, kept only so
   `pip install "meshprovision[ble]"` stays valid — see
   [Installation](installation.md) for why it's a no-op today.
6. **`is_managed` defaults to `false`, with a safety gate** — see
   [The admin-key model](security.md#the-admin-key-model).
7. **The example naming pattern is the generic `MT{n}{n}` (1296
   names)**, not the specification's `D0h{n}`, which the 4-byte
   `short_name` cap would have limited to 36 nodes. "MT" is short for
   Meshtastic — a deliberately non-personal prefix. Fully configurable;
   the validator is what keeps a custom pattern honest.
8. **A single `mesh` console script with subcommands**, replacing the
   specification's two `meshprovision-*` executables (which stuttered).
   The read-only guarantee of `mesh status` is preserved by code and by
   test, not by binary separation.
9. **`data/known_bad_keys.txt` is committed but holds only 7 verified
   X25519 small-order points** — no public CVE-2025-52464 key list
   exists. See [What `known_bad_keys.txt` does and does NOT
   cover](security.md#what-dataknown_bad_keystxt-does-and-does-not-cover).
