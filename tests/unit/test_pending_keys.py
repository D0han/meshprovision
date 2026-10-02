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
        node_id=_NODE, public=kp.public, private=kp.private, created_ts=datetime.now(tz=UTC)
    )

    assert pending.matches(public=kp.public, private=kp.private) is True
    assert pending.matches(public=kp.public, private=kp.private.reveal()) is True
    assert pending.matches(public=other.public, private=kp.private) is False
    assert pending.matches(public=kp.public, private=other.private) is False
    assert pending.matches(public=other.public, private=other.private) is False
