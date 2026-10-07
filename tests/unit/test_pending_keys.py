"""Tests for meshprovision.db.pending_keys."""

from __future__ import annotations

import json
import stat
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.crypto.keys import KeyPair
from meshprovision.db import pending_keys
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit

_NODE = NodeId.from_hex("deadbe01")
_OTHER_NODE = NodeId.from_hex("cafe0002")


def test_pending_key_path_is_in_the_targets_backup_dir_and_never_collides(tmp_path: Path) -> None:
    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)

    assert path.parent == tmp_path / "backups"
    assert path.name == "nodes_db.pending-deadbe01.json"

    # Never matches atomic_writer's timestamped-backup regex/glob (stem
    # immediately followed by "." here, never the "-" a backup name
    # requires) -- see pending_key_path's own docstring.
    from meshprovision.db.backups import _backup_name_re

    assert _backup_name_re(db_path).fullmatch(path.name) is None


def test_write_then_load_round_trips(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    kp = keypair_factory()
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)

    pending_keys.write_pending(db_path, _NODE, kp, now=now)
    loaded = pending_keys.load_pending(db_path, _NODE)

    assert loaded is not None
    assert loaded.node_id == _NODE
    assert loaded.public == kp.public
    assert loaded.private.reveal() == kp.private.reveal()
    assert loaded.created_ts == now


def test_write_pending_creates_the_file_at_mode_0600(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    pending_keys.write_pending(db_path, _NODE, keypair_factory(), now=datetime.now(tz=UTC))

    path = pending_keys.pending_key_path(db_path, _NODE)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_load_pending_is_none_when_absent(tmp_path: Path) -> None:
    assert pending_keys.load_pending(tmp_path / "nodes_db.ods", _NODE) is None


def test_load_pending_is_none_and_warns_when_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"irrelevant")

    def _raise_permission_error(self: Path) -> bytes:
        raise PermissionError("Permission denied")

    monkeypatch.setattr(Path, "read_bytes", _raise_permission_error)

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "Could not read pending keypair" in caplog.text
    assert str(path) in caplog.text


def test_load_pending_is_none_and_warns_when_path_is_a_directory(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)
    path.mkdir(parents=True)

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "Could not read pending keypair" in caplog.text
    assert str(path) in caplog.text


def test_load_pending_is_none_and_warns_on_malformed_json(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"not json")

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "Malformed pending keypair" in caplog.text


def test_load_pending_is_none_and_warns_on_unrecognized_format(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"format": 99, "node_id": _NODE.hex}))

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "unrecognized format" in caplog.text


@pytest.mark.parametrize(
    "payload",
    [
        {"format": 1, "node_id": "deadbe01"},
        {
            "format": 1,
            "node_id": "deadbe01",
            "public": "!!!not-b64",
            "private": "AA==",
            "created_ts": "2026-01-01T00:00:00+00:00",
        },
        {
            "format": 1,
            "node_id": "deadbe01",
            "public": "AA==",
            "private": "AA==",
            "created_ts": "not-a-date",
        },
    ],
    ids=["missing_fields", "bad_base64", "bad_timestamp"],
)
def test_load_pending_is_none_and_warns_on_malformed_content(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, payload: dict[str, object]
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload))

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "Malformed pending keypair" in caplog.text


@pytest.mark.parametrize(
    "created_ts",
    ["9999-12-31T23:59:59-05:00", "0001-01-01T00:00:00+01:00", 1767225600],
    ids=["past_max_in_utc", "before_min_in_utc", "not_a_string"],
)
def test_load_pending_is_none_and_warns_on_an_unusable_timestamp(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    keypair_factory: Callable[[], KeyPair],
    created_ts: object,
) -> None:
    """A timestamp past the datetime range once shifted to UTC raised OverflowError.

    ``mesh provision`` calls ``load_pending`` unprotected, so that crashed
    every provisioning run of the node until the file was deleted by hand.
    """
    db_path = tmp_path / "nodes_db.ods"
    pending_keys.write_pending(db_path, _NODE, keypair_factory(), now=datetime.now(tz=UTC))
    path = pending_keys.pending_key_path(db_path, _NODE)
    payload = json.loads(path.read_text())
    payload["created_ts"] = created_ts
    path.write_text(json.dumps(payload))

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "Malformed pending keypair" in caplog.text


def test_load_pending_is_none_and_warns_on_wrong_length_key(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import base64

    db_path = tmp_path / "nodes_db.ods"
    path = pending_keys.pending_key_path(db_path, _NODE)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "format": 1,
                "node_id": _NODE.hex,
                "public": base64.b64encode(b"too short").decode("ascii"),
                "private": base64.b64encode(b"\x00" * 32).decode("ascii"),
                "created_ts": "2026-01-01T00:00:00+00:00",
            }
        )
    )

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "wrong-length key" in caplog.text


def test_load_pending_is_none_and_warns_when_node_id_does_not_match(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair], caplog: pytest.LogCaptureFixture
) -> None:
    """Defense in depth: the path is already keyed by node id, but content is checked too."""
    db_path = tmp_path / "nodes_db.ods"
    pending_keys.write_pending(db_path, _NODE, keypair_factory(), now=datetime.now(tz=UTC))

    # Overwrite the file at _NODE's own path with a payload naming a
    # different node -- simulating a hand-edited or corrupted sidecar.
    path = pending_keys.pending_key_path(db_path, _NODE)
    data = json.loads(path.read_bytes())
    data["node_id"] = _OTHER_NODE.hex
    path.write_text(json.dumps(data))

    with caplog.at_level("WARNING"):
        assert pending_keys.load_pending(db_path, _NODE) is None
    assert "names node" in caplog.text


def test_clear_pending_removes_the_file(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    db_path = tmp_path / "nodes_db.ods"
    pending_keys.write_pending(db_path, _NODE, keypair_factory(), now=datetime.now(tz=UTC))
    path = pending_keys.pending_key_path(db_path, _NODE)
    assert path.is_file()

    pending_keys.clear_pending(db_path, _NODE)

    assert not path.exists()


def test_clear_pending_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "nodes_db.ods"
    pending_keys.clear_pending(db_path, _NODE)
    pending_keys.clear_pending(db_path, _NODE)  # does not raise


def test_matches_requires_both_halves_to_match(keypair_factory: Callable[[], KeyPair]) -> None:
    kp = keypair_factory()
    other = keypair_factory()
    pending = pending_keys.PendingKeypair(
        node_id=_NODE,
        public=kp.public,
        private=kp.private,
        created_ts=datetime.now(tz=UTC),
        path=Path("nodes_db.pending-deadbe01.json"),
    )

    assert pending.matches(public=kp.public, private=kp.private) is True
    assert pending.matches(public=kp.public, private=kp.private.reveal()) is True
    assert pending.matches(public=other.public, private=kp.private) is False
    assert pending.matches(public=kp.public, private=other.private) is False
    assert pending.matches(public=other.public, private=other.private) is False


def _linked_db(tmp_path: Path) -> tuple[Path, Path]:
    """Build ``ws/fleet.ods`` -> ``shared/nodes_db.ods``: one database, two spellings."""
    real = tmp_path / "shared" / "nodes_db.ods"
    real.parent.mkdir()
    real.write_bytes(b"db")
    link = tmp_path / "ws" / "fleet.ods"
    link.parent.mkdir()
    link.symlink_to(real)
    return real, link


def _older_spelling_file(real: Path, name: str, node_id: NodeId, keypair: KeyPair) -> Path:
    """Write a pending file the way a version naming it after the path as given did."""
    pending_keys.write_pending(real, node_id, keypair, now=datetime.now(tz=UTC))
    current = pending_keys.pending_key_path(real, node_id)
    older = current.with_name(f"{name}.pending-{node_id.hex}.json")
    current.rename(older)
    return older


@pytest.mark.parametrize(
    "write_via_link", [True, False], ids=["written-via-link", "written-via-real"]
)
def test_pending_keypair_is_found_under_either_spelling_of_a_symlinked_db(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair], write_via_link: bool
) -> None:
    """Interrupted via one spelling, re-run via the other: the key must be recovered."""
    real, link = _linked_db(tmp_path)
    kp = keypair_factory()
    writer, reader = (link, real) if write_via_link else (real, link)

    pending_keys.write_pending(writer, _NODE, kp, now=datetime.now(tz=UTC))
    loaded = pending_keys.load_pending(reader, _NODE)

    assert loaded is not None
    assert loaded.public == kp.public
    assert loaded.path.name == f"nodes_db.pending-{_NODE.hex}.json"
    assert pending_keys.pending_key_path(link, _NODE) == pending_keys.pending_key_path(real, _NODE)


def test_load_pending_finds_a_file_named_after_the_symlink(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    real, link = _linked_db(tmp_path)
    kp = keypair_factory()
    older = _older_spelling_file(real, "fleet", _NODE, kp)

    loaded = pending_keys.load_pending(link, _NODE)

    assert loaded is not None
    assert loaded.public == kp.public
    assert loaded.path == older


def test_load_pending_prefers_the_real_files_name_when_both_exist(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    real, link = _linked_db(tmp_path)
    _older_spelling_file(real, "fleet", _NODE, keypair_factory())
    newer = keypair_factory()
    pending_keys.write_pending(real, _NODE, newer, now=datetime.now(tz=UTC))

    loaded = pending_keys.load_pending(link, _NODE)

    assert loaded is not None
    assert loaded.public == newer.public
    assert loaded.path == pending_keys.pending_key_path(real, _NODE)


def test_write_pending_removes_a_superseded_older_spelling(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    real, link = _linked_db(tmp_path)
    older = _older_spelling_file(real, "fleet", _NODE, keypair_factory())

    pending_keys.write_pending(link, _NODE, keypair_factory(), now=datetime.now(tz=UTC))

    assert not older.exists()
    assert pending_keys.pending_key_path(real, _NODE).exists()


def test_clear_pending_removes_both_spellings(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    real, link = _linked_db(tmp_path)
    older = _older_spelling_file(real, "fleet", _NODE, keypair_factory())
    current = pending_keys.pending_key_path(real, _NODE)
    current.write_bytes(older.read_bytes())

    pending_keys.clear_pending(link, _NODE)

    assert not older.exists()
    assert not current.exists()
    assert pending_keys.load_pending(link, _NODE) is None


def test_older_spelling_is_left_to_the_database_that_owns_that_name(
    tmp_path: Path, keypair_factory: Callable[[], KeyPair]
) -> None:
    """``shared/fleet.ods`` is a different database: ``fleet.pending-*`` files are its own."""
    real, link = _linked_db(tmp_path)
    (real.parent / "fleet.ods").write_bytes(b"another fleet")
    theirs = _older_spelling_file(real, "fleet", _NODE, keypair_factory())

    assert pending_keys.load_pending(link, _NODE) is None
    pending_keys.clear_pending(link, _NODE)
    assert theirs.exists()
