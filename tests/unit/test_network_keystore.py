"""``KeyStore``: keys.json per region -- digests only, merged, bounded, read tolerantly."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from meshprovision.network import keystore as keystore_module
from meshprovision.network.buckets import NETWORK_RETENTION_SECONDS
from meshprovision.network.keys import KeyAudit, KeySeen, Severity, observe
from meshprovision.network.keystore import KeyStore
from meshprovision.network.rawpackets import parse_raw
from meshprovision.network.store import STORE_VERSION, region_dirname
from tests.unit.network_fixtures import NOW, node_info, packet, row

pytestmark = pytest.mark.unit

_DIGEST = "sha256:" + "ab" * 8
_ENTRY = KeySeen(
    "ab446357",
    _DIGEST,
    NOW - 7200,
    NOW - 60,
    (1792530000,),
    "AB12",
    "HELTEC_V3",
    "ROUTER",
    True,
    KeyAudit(Severity.WARNING, ("monotonic",)),
)


def _store(tmp_path: Path, now: float = NOW) -> KeyStore:
    return KeyStore(tmp_path / "network", clock=lambda: now)


def _path(tmp_path: Path, region: str = "PL") -> Path:
    return tmp_path / "network" / region_dirname(region) / "keys.json"


def test_sightings_are_written_as_digests_and_read_back(tmp_path: Path) -> None:
    store = _store(tmp_path)

    store.update("PL", [_ENTRY])

    assert store.load("PL") == (_ENTRY,)
    assert json.loads(_path(tmp_path).read_text(encoding="utf-8")) == {
        "version": STORE_VERSION,
        "region": "PL",
        "keys": [
            [
                "ab446357",
                _DIGEST,
                NOW - 7200,
                NOW - 60,
                [1792530000],
                "AB12",
                "HELTEC_V3",
                "ROUTER",
                True,
                ["warning", ["monotonic"]],
            ]
        ],
    }
    assert stat.S_IMODE(_path(tmp_path).stat().st_mode) == 0o600


def test_an_update_merges_and_is_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.update("PL", [_ENTRY])
    later = KeySeen("ab446357", _DIGEST, NOW - 30, NOW - 10, (1792533600,), "New")
    other = KeySeen("11111111", _DIGEST, NOW, NOW, (1792533600,))

    store.update("PL", [later, other])
    store.update("PL", [later, other])

    first, second = store.load("PL")
    assert first == other
    assert (second.first, second.last, second.hours, second.short_name, second.audit) == (
        NOW - 7200,
        NOW - 10,
        (1792530000, 1792533600),
        "New",
        None,
    )


def test_nothing_to_record_writes_nothing(tmp_path: Path) -> None:
    _store(tmp_path).update("PL", [])

    assert not _path(tmp_path).exists()


def test_sightings_past_the_retention_are_dropped(tmp_path: Path) -> None:
    _store(tmp_path).update("PL", [_ENTRY])

    assert _store(tmp_path, _ENTRY.last + NETWORK_RETENTION_SECONDS).load("PL") == (_ENTRY,)
    assert _store(tmp_path, _ENTRY.last + NETWORK_RETENTION_SECONDS + 1).load("PL") == ()


def test_over_the_cap_the_sightings_heard_longest_ago_go_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = [
        KeySeen(f"{n:08x}", _DIGEST, NOW - 1000 + n, NOW - 1000 + n, (1792530000,))
        for n in range(1, 21)
    ]
    store = _store(tmp_path)
    store.update("PL", entries[:1])
    one = _path(tmp_path).stat().st_size
    monkeypatch.setattr(keystore_module, "KEYS_MAX_BYTES", one * 10)

    store.update("PL", entries)

    kept = store.load("PL")
    assert 0 < len(kept) < 20
    assert kept[-1] == entries[-1]
    assert kept[0].node > entries[0].node


def _write(tmp_path: Path, document: object) -> None:
    path = _path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document if isinstance(document, str) else json.dumps(document))


_GOOD = ["11111111", _DIGEST, NOW, NOW, [1792530000], None, None, None, False, None]


@pytest.mark.parametrize(
    ("index", "value"),
    [
        pytest.param(0, "AB446357", id="uppercase-id"),
        pytest.param(1, "sha256:abcd", id="short-digest"),
        pytest.param(2, NOW + 1, id="first-after-last"),
        pytest.param(3, "now", id="last-not-a-number"),
        pytest.param(4, [1792530001], id="hour-not-on-the-hour"),
        pytest.param(4, list(range(0, 169 * 3600, 3600)), id="too-many-hours"),
        pytest.param(5, "", id="blank-name"),
        pytest.param(8, 1, id="derived-not-a-bool"),
        pytest.param(9, ["fatal", []], id="unknown-severity"),
        pytest.param(9, ["warning", [""]], id="blank-check"),
        pytest.param(9, ["warning"], id="audit-too-short"),
    ],
)
def test_a_malformed_entry_is_dropped(tmp_path: Path, index: int, value: object) -> None:
    bad = list(_GOOD)
    bad[index] = value
    bad[0] = bad[0] if index == 0 else "22222222"
    _write(tmp_path, {"version": STORE_VERSION, "region": "PL", "keys": [_GOOD, bad, "x"]})

    assert [entry.node for entry in _store(tmp_path).load("PL")] == ["11111111"]


def test_stored_names_are_made_terminal_safe(tmp_path: Path) -> None:
    entry = list(_GOOD)
    entry[5] = "\x1b[2J"
    entry[9] = ["critical", ["\x1b]0;x"]]
    _write(tmp_path, {"version": STORE_VERSION, "region": "PL", "keys": [entry]})

    (seen,) = _store(tmp_path).load("PL")

    assert seen.short_name == "\\x1b[2J"
    assert seen.audit == KeyAudit(Severity.CRITICAL, ("\\x1b]0;x",))


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("{", id="corrupt"),
        pytest.param({"version": 2, "region": "PL", "keys": []}, id="other-version"),
        pytest.param({"version": STORE_VERSION, "region": "x", "keys": [_GOOD]}, id="other-region"),
        pytest.param({"version": STORE_VERSION, "region": "PL", "keys": {}}, id="not-a-list"),
    ],
)
def test_an_unusable_file_reads_as_empty(tmp_path: Path, document: object) -> None:
    _write(tmp_path, document)

    assert _store(tmp_path).load("PL") == ()


def test_a_long_or_escape_laden_name_is_cut_never_dropped(tmp_path: Path) -> None:
    entry = list(_GOOD)
    entry[5] = "\x1b" * 40
    entry[6] = "x" * 300
    _write(tmp_path, {"version": STORE_VERSION, "region": "PL", "keys": [entry]})

    (seen,) = _store(tmp_path).load("PL")

    assert seen.short_name == ("\\x1b" * 40)[:64]
    assert seen.hw_model == "x" * 64


def test_a_sighting_with_a_hostile_name_survives_the_round_trip(tmp_path: Path) -> None:
    key = bytes(range(1, 33))
    port, payload = node_info(0xAB446357, key, short_name="\x1b" * 17)
    parsed = parse_raw([row(packet(0xAB446357, 7, port=port, payload=payload))], now=NOW)
    store = _store(tmp_path)

    store.update("PL", observe(parsed.keys, frozenset()))

    (loaded,) = store.load("PL")
    assert loaded.node == "ab446357"
    assert loaded.short_name == ("\\x1b" * 17)[:64]
