"""Regenerate ``data/nodes_db.example.ods`` deterministically.

This script is the single source of truth for the example database
shipped in the repository: a handful of obviously-fake, illustrative
``Nodes``/``Keys`` rows, written through the exact same
:mod:`meshprovision.db.nodes`/:mod:`meshprovision.db.keys`/
:mod:`meshprovision.db.ods` machinery the real ``mesh`` CLI uses, so the
example file always demonstrates the real schema -- formulas, dropdowns,
and the frozen header row included.

Every timestamp and key value recorded in the database is fixed, so
re-running this script produces byte-identical ``Nodes``/``Keys``
content on every run -- verified by comparing ``content.xml``,
``styles.xml``, ``settings.xml``, ``meta.xml``, and ``manifest.xml``
across two consecutive runs. The one thing that does vary is each zip
entry's own last-modified timestamp, which ``odfpy``/``zipfile`` stamp
with the current wall-clock time as an artifact of how the ``.ods``
container is serialized; this is outside meshprovision's control and does
not reflect a difference in the actual schema or data. Every key value is
a 32-byte
ASCII placeholder that spells out what it is (``b"EXAMPLE-KEY-DO-NOT-
USE-..."``), so anyone who base64-decodes a cell immediately sees it is
fake -- and every one of them passes
:func:`meshprovision.crypto.weakkeys.audit_public_key` with zero
findings, which this script asserts on every run so a future edit can
never silently break that guarantee.

Usage:
    python scripts/generate_example_db.py
    python scripts/generate_example_db.py -o /tmp/example.ods
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final


def _ensure_package_importable() -> None:
    """Insert the repo's ``src`` directory on ``sys.path`` if needed.

    Lets this script run against a bare checkout, before an editable
    install (``pip install -e .``) has been performed.
    """
    try:
        import meshprovision  # noqa: F401
    except ImportError:
        repo_root = Path(__file__).resolve().parents[1]
        src_dir = repo_root / "src"
        if src_dir.is_dir() and str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))


_ensure_package_importable()

from pydantic import SecretStr  # noqa: E402

from meshprovision.crypto.keys import decode_key, encode_key  # noqa: E402
from meshprovision.db import ods  # noqa: E402
from meshprovision.db.keys import KeyRecord  # noqa: E402
from meshprovision.db.nodes import NodeRecord  # noqa: E402
from meshprovision.db.schema import FirmwareType, KeyType  # noqa: E402
from meshprovision.errors import MeshprovisionError  # noqa: E402

__all__ = ["EXAMPLE_DB_PATH", "EXAMPLE_TIMESTAMP", "build_records", "generate", "main"]

EXAMPLE_DB_PATH: Final[Path] = Path("data/nodes_db.example.ods")
"""Default output path, relative to the current working directory."""

EXAMPLE_TIMESTAMP: Final[datetime] = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
"""Fixed timestamp recorded on every row, so output is byte-reproducible."""

# Each placeholder is exactly 32 ASCII bytes and spells out what it is, so
# anyone who base64-decodes a Keys.key_value cell sees immediately that it
# is fake. None of these are real key material.
_PLACEHOLDER_ADMIN_PUB: Final[bytes] = b"EXAMPLE-KEY-DO-NOT-USE-000000001"
_PLACEHOLDER_ADMIN_PRIV: Final[bytes] = b"EXAMPLE-KEY-DO-NOT-USE-000000002"
_PLACEHOLDER_NODE_PUB: Final[bytes] = b"EXAMPLE-KEY-DO-NOT-USE-000000003"
_PLACEHOLDER_PSK: Final[bytes] = b"EXAMPLE-PSK-DO-NOT-USE-000000001"


def _check_placeholder_round_trips() -> None:
    """Confirm every placeholder key round-trips through encode/decode unchanged.

    Guards against a future edit silently corrupting one of the
    placeholder byte strings (for example truncating it to something
    other than 32 bytes).

    Raises:
        MeshprovisionError: If any placeholder does not round-trip
            byte-for-byte through :func:`~meshprovision.crypto.keys.
            encode_key`/:func:`~meshprovision.crypto.keys.decode_key`.
    """
    for raw in (
        _PLACEHOLDER_ADMIN_PUB,
        _PLACEHOLDER_ADMIN_PRIV,
        _PLACEHOLDER_NODE_PUB,
        _PLACEHOLDER_PSK,
    ):
        if decode_key(encode_key(raw)) != raw:
            raise MeshprovisionError(
                "A placeholder example key no longer round-trips through "
                "encode_key/decode_key unchanged; check it is still exactly 32 bytes."
            )


def build_records() -> tuple[tuple[NodeRecord, ...], tuple[KeyRecord, ...]]:
    """Build the deterministic, illustrative example ``Nodes``/``Keys`` rows.

    Returns:
        ``(nodes, keys)``: 3 node records and 4 key records, all built
        from fixed, obviously-fake data.

    Raises:
        MeshprovisionError: If a placeholder key fails its round-trip
            check (see :func:`_check_placeholder_round_trips`).
    """
    _check_placeholder_round_trips()

    nodes = (
        NodeRecord(
            node_id="deadbe01",
            short_name="MT01",
            long_name="Meshtastic MT01",
            hw_model="HELTEC_V3",
            firmware_type=FirmwareType.VANILLA,
            firmware_version="2.7.11.example",
            gps_lat=52.2297,
            gps_lon=21.0122,
            gps_alt=110,
            first_added_ts=EXAMPLE_TIMESTAMP,
            last_updated_ts=EXAMPLE_TIMESTAMP,
            authorized_admin_keys=("example-admin_pub",),
            notes="EXAMPLE ROW - fake node id and fake key material. Not a real device.",
            role="CLIENT",
            region="EU_868",
            ble_pin=SecretStr("014725"),
        ),
        NodeRecord(
            node_id="deadbe02",
            short_name="MT02",
            long_name="Meshtastic MT02",
            hw_model="TRACKER_T1000_E",
            firmware_type=FirmwareType.LORANET,
            gps_lat=50.0647,
            gps_lon=19.9450,
            gps_alt=219,
            first_added_ts=EXAMPLE_TIMESTAMP,
            last_updated_ts=EXAMPLE_TIMESTAMP,
            role="TRACKER",
            region="EU_868",
            # Leading zeros are the point of this row: ble_pin is a text
            # column so "000042" round-trips as six characters, not 42.
            ble_pin=SecretStr("000042"),
        ),
        NodeRecord(
            node_id="deadbe03",
            short_name="MT03",
            long_name="Meshtastic MT03",
            hw_model="RAK4631",
            firmware_type=FirmwareType.OTHER,
            first_added_ts=EXAMPLE_TIMESTAMP,
            last_updated_ts=EXAMPLE_TIMESTAMP,
            authorized_admin_keys=(),
            notes=("EXAMPLE ROW - a node deliberately provisioned with zero admin keys."),
            role="ROUTER",
            region="EU_868",
        ),
    )

    keys = (
        KeyRecord.from_material(
            "example-admin",
            KeyType.ADMIN_PUBLIC,
            _PLACEHOLDER_ADMIN_PUB,
            created_ts=EXAMPLE_TIMESTAMP,
        ),
        KeyRecord.from_material(
            "example-admin",
            KeyType.ADMIN_PRIVATE,
            _PLACEHOLDER_ADMIN_PRIV,
            created_ts=EXAMPLE_TIMESTAMP,
        ),
        KeyRecord.from_material(
            "deadbe01", KeyType.ADMIN_PUBLIC, _PLACEHOLDER_NODE_PUB, created_ts=EXAMPLE_TIMESTAMP
        ),
        KeyRecord.from_material(
            "deadbe01", KeyType.CHANNEL_PSK, _PLACEHOLDER_PSK, created_ts=EXAMPLE_TIMESTAMP
        ),
    )
    return nodes, keys


def generate(path: Path = EXAMPLE_DB_PATH) -> Path:
    """Build the example records and write them to ``path``.

    ``backup=False`` is deliberate: regenerating the *example* file must
    never litter ``data/backups/`` with backups of a fixture.

    Args:
        path: Output path for the generated ``.ods`` file.

    Returns:
        ``path``, unchanged.

    Raises:
        MeshprovisionError: If a placeholder key fails its round-trip
            check.
        AtomicWriteError: If the write fails.
    """
    nodes, keys = build_records()
    ods.write_database(
        path,
        nodes=[record.to_row() for record in nodes],
        keys=[record.to_row() for record in keys],
        backup=False,
    )
    return path


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        The configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="generate_example_db.py",
        description=(
            "Regenerate data/nodes_db.example.ods deterministically, with a handful "
            "of obviously-fake illustrative rows."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=EXAMPLE_DB_PATH,
        help=f"Output .ods path (default: {EXAMPLE_DB_PATH}).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the generate-example-db CLI.

    Args:
        argv: Command-line arguments, excluding the program name. When
            ``None``, taken from ``sys.argv``.

    Returns:
        Always ``0``.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    nodes, keys = build_records()
    written = generate(args.output)
    print(f"wrote {written} ({len(nodes)} nodes, {len(keys)} keys)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
