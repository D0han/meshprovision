"""Tests for meshprovision.provisioning.backup."""

from __future__ import annotations

import base64
import json
import traceback
from typing import TYPE_CHECKING

import pytest
import yaml
from meshtastic.protobuf import clientonly_pb2, config_pb2

from meshprovision.datasources.base import SOURCE_LORANET
from meshprovision.datasources.models import NodeObservation
from meshprovision.errors import BackupParseError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import backup

if TYPE_CHECKING:
    from collections.abc import Callable

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit


def _windows(token: str, size: int = 8) -> list[str]:
    """Every contiguous ``size``-char substring of ``token``.

    Used to catch a partial key leak through truncation or line-wrapping,
    not just a leak of the whole token. 8 chars of base64 is 48 bits, so a
    coincidental match is negligible.
    """
    return [token[i : i + size] for i in range(max(1, len(token) - size + 1))]


def _make_cfg_bytes(
    *,
    long_name: str = "Meshtastic MT01",
    short_name: str = "MT01",
    channel_url: str = "",
    public_key: bytes = b"",
    private_key: bytes = b"",
    fixed_position: tuple[float, float, int] | None = None,
) -> bytes:
    profile = clientonly_pb2.DeviceProfile()
    profile.long_name = long_name
    profile.short_name = short_name
    if channel_url:
        profile.channel_url = channel_url
    profile.config.lora.region = config_pb2.Config.LoRaConfig.EU_868
    profile.config.device.role = config_pb2.Config.DeviceConfig.CLIENT
    if public_key:
        profile.config.security.public_key = public_key
    if private_key:
        profile.config.security.private_key = private_key
    if fixed_position is not None:
        lat, lon, alt = fixed_position
        profile.fixed_position.latitude_i = int(lat * 1e7)
        profile.fixed_position.longitude_i = int(lon * 1e7)
        profile.fixed_position.altitude = alt
    return bytes(profile.SerializeToString())


# --- sniff_format ------------------------------------------------------


def test_sniff_format_detects_device_profile_protobuf() -> None:
    raw = _make_cfg_bytes()
    assert backup.sniff_format(raw) is backup.BackupFormat.PROFILE_CFG


def test_sniff_format_detects_nodedb_json() -> None:
    raw = json.dumps({"schemaVersion": 1, "nodes": []}).encode()
    assert backup.sniff_format(raw) is backup.BackupFormat.NODEDB_JSON


def test_sniff_format_detects_profile_yaml() -> None:
    raw = b"owner: Test\nowner_short: TST\n"
    assert backup.sniff_format(raw) is backup.BackupFormat.PROFILE_YAML


def test_sniff_format_rejects_empty_input() -> None:
    assert backup.sniff_format(b"") is None


def test_sniff_format_rejects_arbitrary_garbage() -> None:
    assert backup.sniff_format(b"\x00\x01not a valid anything at all zzz\xff") is None


def test_sniff_format_rejects_unrelated_json() -> None:
    """A JSON document without nodes/schemaVersion is not a node-db export."""
    assert backup.sniff_format(json.dumps({"hello": "world"}).encode()) is None


def test_sniff_format_rejects_unrelated_yaml() -> None:
    """A YAML mapping without any profile marker key is not a profile."""
    assert backup.sniff_format(b"hello: world\nfoo: bar\n") is None


def test_sniff_format_rejects_plain_text() -> None:
    assert backup.sniff_format(b"just some plain text, not any format at all") is None


# --- parse_profile_cfg ---------------------------------------------------


def test_parse_profile_cfg_round_trips_names_and_config() -> None:
    raw = _make_cfg_bytes(long_name="Meshtastic MT01", short_name="MT01")
    parsed = backup.parse_profile_cfg(raw, source="test.cfg")
    assert parsed.long_name == "Meshtastic MT01"
    assert parsed.short_name == "MT01"
    assert parsed.source == "test.cfg"
    assert parsed.public_key is None
    assert parsed.private_key is None
    assert parsed.channel is None
    assert parsed.fixed_position is None


def test_parse_profile_cfg_extracts_keys() -> None:
    pub = bytes(range(32))
    priv = bytes(range(32, 64))
    raw = _make_cfg_bytes(public_key=pub, private_key=priv)
    parsed = backup.parse_profile_cfg(raw, source="test.cfg")
    assert parsed.public_key == pub
    assert parsed.private_key is not None
    assert parsed.private_key.reveal() == priv


def test_parse_profile_cfg_extracts_fixed_position() -> None:
    raw = _make_cfg_bytes(fixed_position=(52.0, 21.0, 100))
    parsed = backup.parse_profile_cfg(raw, source="test.cfg")
    assert parsed.fixed_position is not None
    assert parsed.fixed_position.latitude == pytest.approx(52.0)
    assert parsed.fixed_position.longitude == pytest.approx(21.0)
    assert parsed.fixed_position.altitude == 100


def test_parse_profile_cfg_rejects_garbage() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_profile_cfg(b"\x00not a device profile\xff", source="bad.cfg")


def test_parse_profile_cfg_repr_never_exposes_key_bytes() -> None:
    pub = bytes(range(32))
    priv = bytes(range(32, 64))
    raw = _make_cfg_bytes(public_key=pub, private_key=priv)
    parsed = backup.parse_profile_cfg(raw, source="test.cfg")
    text = repr(parsed)
    assert pub.hex() not in text
    assert priv.hex() not in text
    assert base64.b64encode(pub).decode() not in text
    assert base64.b64encode(priv).decode() not in text


# --- decode_channel_url ---------------------------------------------------


def test_decode_channel_url_recovers_primary_channel() -> None:
    info = backup.decode_channel_url("https://meshtastic.org/e/#CgMSAQE")
    assert info is not None
    assert info.psk == b"\x01"


def test_decode_channel_url_returns_none_for_empty_fragment() -> None:
    assert backup.decode_channel_url("https://meshtastic.org/e/#") is None


def test_decode_channel_url_returns_none_for_malformed_base64() -> None:
    assert backup.decode_channel_url("https://meshtastic.org/e/#not!!valid$$base64") is None


def test_decode_channel_url_returns_none_without_fragment() -> None:
    assert backup.decode_channel_url("https://meshtastic.org/e/") is None


def test_parse_profile_cfg_undecodable_channel_url_warns() -> None:
    """Regression test for Round 35's backup-adoption review, Finding 5.

    A present-but-undecodable channel_url must not silently degrade to
    "no channel" -- indistinguishable from a node that genuinely has
    none configured -- with zero warning.
    """
    raw = _make_cfg_bytes(channel_url="https://meshtastic.org/e/#not!!valid$$base64")
    profile = backup.parse_profile_cfg(raw, source="p.cfg")

    assert profile.channel is None
    assert len(profile.warnings) == 1
    assert "could not be decoded" in profile.warnings[0]


def test_parse_profile_cfg_missing_channel_url_is_silent() -> None:
    """No channel_url at all is genuinely nothing to warn about."""
    raw = _make_cfg_bytes()
    profile = backup.parse_profile_cfg(raw, source="p.cfg")

    assert profile.channel is None
    assert profile.warnings == ()


def test_merge_backups_surfaces_the_undecodable_channel_url_warning() -> None:
    raw = _make_cfg_bytes(channel_url="https://meshtastic.org/e/#not!!valid$$base64")
    profile = backup.parse_profile_cfg(raw, source="p.cfg")
    bundle = backup.merge_backups(profile=profile)

    assert any("could not be decoded" in w for w in bundle.warnings)


def test_decode_channel_url_repr_never_exposes_psk_bytes() -> None:
    info = backup.decode_channel_url("https://meshtastic.org/e/#CgMSAQE")
    assert info is not None
    assert "\\x01" not in repr(info)
    assert "01" not in repr(info).split("psk=")[-1].split(">")[0].replace("1B:", "")


# --- parse_profile_yaml ---------------------------------------------------


_YAML_TEXT = """
owner: Meshtastic MT02
owner_short: MT02
channel_url: https://meshtastic.org/e/#CgMSAQE
config:
  lora:
    region: EU_868
  device:
    role: CLIENT
  security:
    publicKey: base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
    privateKey: base64:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
module_config:
  mqtt:
    enabled: true
location:
  lat: 52.0
  lon: 21.0
  alt: 100
"""


def test_parse_profile_yaml_round_trips_fields() -> None:
    parsed = backup.parse_profile_yaml(_YAML_TEXT, source="test.yaml")
    assert parsed.long_name == "Meshtastic MT02"
    assert parsed.short_name == "MT02"
    assert parsed.public_key is not None
    assert parsed.private_key is not None
    assert parsed.channel is not None
    assert parsed.fixed_position is not None
    assert parsed.fixed_position.latitude == pytest.approx(52.0)


def test_parse_profile_yaml_strips_base64_prefix() -> None:
    parsed = backup.parse_profile_yaml(_YAML_TEXT, source="test.yaml")
    expected_pub = base64.b64decode("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
    assert parsed.public_key == expected_pub


def test_parse_profile_yaml_undecodable_channel_url_warns() -> None:
    """Regression test for Round 35's backup-adoption review, Finding 5."""
    text = "owner: MT02\nchannel_url: https://meshtastic.org/e/#not!!valid$$base64\n"
    parsed = backup.parse_profile_yaml(text, source="test.yaml")

    assert parsed.channel is None
    assert len(parsed.warnings) == 1
    assert "could not be decoded" in parsed.warnings[0]


def test_parse_profile_yaml_rejects_non_mapping() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_profile_yaml("- just\n- a\n- list\n", source="bad.yaml")


def test_parse_profile_yaml_rejects_invalid_yaml() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_profile_yaml("owner: [unterminated", source="bad.yaml")


@pytest.mark.parametrize(
    "make_text",
    [
        pytest.param(
            lambda key: f'owner: test\nconfig:\n  security:\n    privateKey: "base64:{key}\n',
            id="unclosed_quote",
        ),
        pytest.param(
            lambda key: f"owner: test\nconfig:\n  security:\n    privateKey: base64:{key}\t\n",
            id="trailing_tab",
        ),
        pytest.param(
            lambda key: (
                "owner: test\nconfig:\n  security:\n    privateKey: base64:"
                f"{key[:20]}\n\t{key[20:]}\n"
            ),
            id="tab_indent_after_key",
        ),
    ],
)
def test_parse_profile_yaml_invalid_yaml_error_never_echoes_key_material(
    make_text: Callable[[str], str], keypair_factory: Callable[[], KeyPair]
) -> None:
    """Round 37 aspect 2 S7 / aspect 5 T12.

    ``MarkedYAMLError.__str__`` calls ``get_snippet()``, which quotes the offending
    source line. When a malformed backup's syntax error lands on or near a
    ``privateKey:`` line, that snippet echoes a fragment of the key -- reproduced
    here with an unclosed quote, a stray tab right after the key, and a
    tab-indented continuation line right after the key. The fix must build the
    message from ``problem``/``context``/``problem_mark`` only, never ``str(exc)``,
    and must raise ``from None`` so the original exception (and its snippet) never
    reaches a DEBUG traceback either.
    """
    key = base64.b64encode(keypair_factory().private.reveal()).decode()
    text = make_text(key)

    with pytest.raises(yaml.YAMLError) as yaml_excinfo:
        yaml.safe_load(text)
    mark = yaml_excinfo.value.problem_mark
    assert mark is not None

    with pytest.raises(BackupParseError) as excinfo:
        backup.parse_profile_yaml(text, source="bad.yaml")

    err = excinfo.value
    message = str(err)
    rendered_traceback = "".join(traceback.format_exception(err))

    for window in _windows(key):
        assert window not in message
        assert window not in rendered_traceback

    assert f"line {mark.line + 1}, column {mark.column + 1}" in message
    assert err.__cause__ is None
    assert err.__suppress_context__ is True


def test_parse_profile_yaml_rejects_invalid_config_shape() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_profile_yaml(
            "owner: Test\nconfig:\n  lora:\n    txPower: not_a_number\n", source="s.yaml"
        )


# --- parse_nodedb_json ---------------------------------------------------


def _nodedb_payload(
    *, schema_version: object = 1, my_node_num: int = 2697256389
) -> dict[str, object]:
    return {
        "schemaVersion": schema_version,
        "exportedAt": "2026-01-01T00:00:00Z",
        "myNodeNum": my_node_num,
        "nodes": [
            {
                "num": my_node_num,
                "id": "!a0c4ddc5",
                "longName": "Meshtastic MT02",
                "shortName": "MT02",
                "hwModel": "TBEAM",
                "role": "CLIENT",
                "publicKey": base64.b64encode(bytes(range(32))).decode(),
                "metadata": {"firmwareVersion": "2.6.11"},
            },
            {"num": 999},
        ],
    }


def test_parse_nodedb_json_finds_own_entry() -> None:
    raw = json.dumps(_nodedb_payload()).encode()
    parsed = backup.parse_nodedb_json(raw, source="nodedb.json")
    entry = parsed.own_entry()
    assert entry is not None
    assert entry.long_name == "Meshtastic MT02"
    assert entry.hw_model == "TBEAM"
    assert entry.public_key == bytes(range(32))
    assert entry.firmware_version == "2.6.11"
    assert entry.node_id == NodeId.from_int(2697256389)


def test_parse_nodedb_json_wrong_length_public_key_warns_and_is_absent() -> None:
    """Regression test for Round 35's backup-adoption review, Finding 7.

    A truncated/corrupt publicKey field decodes as valid base64 to the
    wrong byte length -- silently accepting it produced a misleading
    "these backups appear to be for different nodes" conflict diagnosis
    downstream, for what is actually one corrupt field.
    """
    payload = _nodedb_payload()
    payload["nodes"][0]["publicKey"] = base64.b64encode(bytes(range(16))).decode()
    parsed = backup.parse_nodedb_json(json.dumps(payload).encode(), source="nodedb.json")

    entry = parsed.own_entry()
    assert entry is not None
    assert entry.public_key is None
    assert len(parsed.warnings) == 1
    assert "16 byte(s)" in parsed.warnings[0]
    assert "treating it as absent" in parsed.warnings[0]


def test_parse_nodedb_json_invalid_base64_public_key_warns_and_is_absent() -> None:
    """A publicKey that isn't valid base64 warns, matching the wrong-length case."""
    payload = _nodedb_payload()
    payload["nodes"][0]["publicKey"] = "AAAA!!!!not-base64"
    parsed = backup.parse_nodedb_json(json.dumps(payload).encode(), source="nodedb.json")

    entry = parsed.own_entry()
    assert entry is not None
    assert entry.public_key is None
    assert len(parsed.warnings) == 1
    assert "not valid base64" in parsed.warnings[0]
    assert f"{payload['myNodeNum']:08x}" in parsed.warnings[0]


def test_parse_nodedb_json_own_entry_none_when_my_node_num_absent() -> None:
    payload = _nodedb_payload()
    del payload["myNodeNum"]
    parsed = backup.parse_nodedb_json(json.dumps(payload).encode(), source="nodedb.json")
    assert parsed.own_entry() is None


def test_parse_nodedb_json_own_entry_none_when_no_match() -> None:
    payload = _nodedb_payload()
    payload["myNodeNum"] = 424242
    parsed = backup.parse_nodedb_json(json.dumps(payload).encode(), source="nodedb.json")
    assert parsed.own_entry() is None


def test_parse_nodedb_json_skips_malformed_entries() -> None:
    payload = {"schemaVersion": 1, "nodes": [{"no_num": True}, {"num": 42}]}
    parsed = backup.parse_nodedb_json(json.dumps(payload).encode(), source="nodedb.json")
    assert len(parsed.entries) == 1
    assert parsed.entries[0].num == 42


def test_parse_nodedb_json_warns_on_unrecognized_schema_version() -> None:
    parsed = backup.parse_nodedb_json(
        json.dumps(_nodedb_payload(schema_version=99)).encode(), source="nodedb.json"
    )
    assert any("schemaVersion" in warning for warning in parsed.warnings)


def test_parse_nodedb_json_rejects_missing_nodes_array() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_nodedb_json(json.dumps({"schemaVersion": 1}).encode(), source="bad.json")


def test_parse_nodedb_json_rejects_non_object_top_level() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_nodedb_json(json.dumps([1, 2, 3]).encode(), source="bad.json")


def test_parse_nodedb_json_rejects_invalid_utf8() -> None:
    with pytest.raises(BackupParseError):
        backup.parse_nodedb_json(b"\xff\xfe not utf-8", source="bad.json")


def test_nodedb_entry_repr_never_exposes_public_key_bytes() -> None:
    parsed = backup.parse_nodedb_json(json.dumps(_nodedb_payload()).encode(), source="n.json")
    entry = parsed.own_entry()
    assert entry is not None
    assert base64.b64encode(bytes(range(32))).decode() not in repr(entry)


# --- merge_backups ---------------------------------------------------


def test_merge_backups_requires_at_least_one_file() -> None:
    with pytest.raises(BackupParseError):
        backup.merge_backups()


def test_merge_backups_profile_only() -> None:
    profile = backup.parse_profile_cfg(_make_cfg_bytes(), source="p.cfg")
    bundle = backup.merge_backups(profile=profile)
    assert bundle.long_name == "Meshtastic MT01"
    assert bundle.nodedb_entry is None


def test_merge_backups_nodedb_only() -> None:
    nodedb = backup.parse_nodedb_json(json.dumps(_nodedb_payload()).encode(), source="n.json")
    bundle = backup.merge_backups(nodedb=nodedb)
    assert bundle.profile is None
    assert bundle.long_name == "Meshtastic MT02"


def test_merge_backups_conflicting_long_name_raises() -> None:
    profile = backup.parse_profile_cfg(_make_cfg_bytes(long_name="Node A"), source="p.cfg")
    payload = _nodedb_payload()
    payload["nodes"][0]["longName"] = "Node B"
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    with pytest.raises(BackupParseError, match="Conflicting long_name"):
        backup.merge_backups(profile=profile, nodedb=nodedb)


def test_merge_backups_name_conflict_with_matching_keys_warns_instead_of_raising() -> None:
    """Regression test for Round 35's backup-adoption review, Finding 6.

    Two backups are snapshots taken at different times -- a long_name
    disagreement when both carry the *same* public key is far more
    likely a rename between exports than genuinely different nodes, and
    must not hard-refuse the operator's own file history.
    """
    kp_material = bytes(range(32))
    profile = backup.parse_profile_cfg(
        _make_cfg_bytes(long_name="New Name", short_name="MT02", public_key=kp_material),
        source="fresh.cfg",
    )
    payload = _nodedb_payload()
    payload["nodes"][0]["longName"] = "Old Name"
    payload["nodes"][0]["publicKey"] = base64.b64encode(kp_material).decode()
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="stale.json")

    bundle = backup.merge_backups(profile=profile, nodedb=nodedb)

    assert any("looks like a rename" in w for w in bundle.warnings)
    # The profile's own name still wins, per BackupBundle.long_name's
    # documented precedence.
    assert bundle.long_name == "New Name"


def test_merge_backups_conflicting_public_key_raises() -> None:
    profile = backup.parse_profile_cfg(
        _make_cfg_bytes(
            long_name="Meshtastic MT02", short_name="MT02", public_key=bytes(range(32))
        ),
        source="p.cfg",
    )
    payload = _nodedb_payload()
    payload["nodes"][0]["publicKey"] = base64.b64encode(bytes(reversed(range(32)))).decode()
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    with pytest.raises(BackupParseError, match="Conflicting public key"):
        backup.merge_backups(profile=profile, nodedb=nodedb)


def test_merge_backups_agreeing_names_and_key_succeeds() -> None:
    pub = bytes(range(32))
    profile = backup.parse_profile_cfg(
        _make_cfg_bytes(long_name="Meshtastic MT02", short_name="MT02", public_key=pub),
        source="p.cfg",
    )
    payload = _nodedb_payload()
    payload["nodes"][0]["publicKey"] = base64.b64encode(pub).decode()
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    bundle = backup.merge_backups(profile=profile, nodedb=nodedb)
    assert bundle.public_key == pub


def test_merge_backups_warns_when_my_node_num_matches_nothing() -> None:
    payload = _nodedb_payload()
    payload["myNodeNum"] = 1
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    bundle = backup.merge_backups(nodedb=nodedb)
    assert any("was not found" in warning for warning in bundle.warnings)


# --- live_config_from_backup ---------------------------------------------------


def test_live_config_from_backup_profile_only() -> None:
    pub = bytes(range(32))
    priv = bytes(range(32, 64))
    profile = backup.parse_profile_cfg(
        _make_cfg_bytes(public_key=pub, private_key=priv), source="p.cfg"
    )
    bundle = backup.merge_backups(profile=profile)
    node_id = NodeId.from_hex("a0cb5cc4")

    live = backup.live_config_from_backup(bundle, node_id=node_id)

    assert live.node_id == node_id
    assert live.security.public_key == pub
    assert live.security.has_private_key
    assert live.value("lora", "region") == "EU_868"
    assert live.value("device", "role") == "CLIENT"
    assert live.hw_model == ""
    assert live.firmware_version == ""


def test_live_config_from_backup_nodedb_only_fills_hw_model_and_firmware() -> None:
    """A node-db-only bundle fills hw_model/firmware_version/public_key/role.

    It fills those from `entry` when genuinely reported, but must NOT
    fabricate region or any other config-section value from the bare
    protobuf default it builds internally -- there is no .cfg/.yaml
    behind it, and NodeDbEntry has no region field at all, so a region
    reading here can never be anything but a fabricated protobuf
    zero-value.
    """
    nodedb = backup.parse_nodedb_json(json.dumps(_nodedb_payload()).encode(), source="n.json")
    bundle = backup.merge_backups(nodedb=nodedb)
    node_id = NodeId.from_int(2697256389)

    live = backup.live_config_from_backup(bundle, node_id=node_id)

    assert live.hw_model == "TBEAM"
    assert live.firmware_version == "2.6.11"
    assert live.value("device", "role") == "CLIENT"  # genuinely reported by entry.role
    assert live.value("lora", "region") is None  # NodeDbEntry has no region field at all
    assert live.role_raw is None
    assert live.module_sections == {}
    assert live.security.public_key == bytes(range(32))


def test_live_config_from_backup_nodedb_only_role_absent_from_entry_is_not_fabricated() -> None:
    """Regression test for Round 35's backup-adoption review, Finding 1.

    A node-db-only bundle whose entry has no ``role`` key at all must not
    report the protobuf's own default ("CLIENT") as though it were a real
    observation. Before this fix, `live.value("device", "role")` always
    read back "CLIENT" for a node-db-only bundle regardless of what (if
    anything) the entry actually reported.
    """
    payload = _nodedb_payload()
    del payload["nodes"][0]["role"]  # type: ignore[index]
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    bundle = backup.merge_backups(nodedb=nodedb)
    node_id = NodeId.from_int(2697256389)

    live = backup.live_config_from_backup(bundle, node_id=node_id)

    assert live.value("device", "role") is None
    assert live.role_raw is None
    assert live.sections == {}


def test_live_config_from_backup_nodedb_only_unrecognized_role_is_flagged_not_defaulted() -> None:
    """Regression test for Round 35's backup-adoption review, Finding 2.

    An entry.role this build's role_table doesn't recognize must not
    silently fall back to the protobuf default ("CLIENT") -- it must
    surface via role_raw (mirroring hw_model_raw) so
    build_adoption_report can warn instead of guessing.
    """
    payload = _nodedb_payload()
    payload["nodes"][0]["role"] = "FUTURE_ROLE_9"  # type: ignore[index]
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    bundle = backup.merge_backups(nodedb=nodedb)
    node_id = NodeId.from_int(2697256389)

    live = backup.live_config_from_backup(bundle, node_id=node_id)

    assert live.value("device", "role") is None
    assert live.role_raw == "FUTURE_ROLE_9"
    assert live.sections == {}


def test_live_config_from_backup_does_not_mutate_the_profile() -> None:
    """Calling this twice must not double-apply mutations to the parsed profile."""
    profile = backup.parse_profile_cfg(_make_cfg_bytes(), source="p.cfg")
    bundle = backup.merge_backups(profile=profile)
    node_id = NodeId.from_hex("a0cb5cc4")

    first = backup.live_config_from_backup(bundle, node_id=node_id)
    second = backup.live_config_from_backup(bundle, node_id=node_id)

    assert first.value("lora", "region") == second.value("lora", "region")


def test_live_config_from_backup_combines_profile_config_with_nodedb_identity() -> None:
    pub = bytes(range(32))
    profile = backup.parse_profile_cfg(
        _make_cfg_bytes(
            long_name="Meshtastic MT02",
            short_name="MT02",
            public_key=pub,
            channel_url="https://meshtastic.org/e/#CgMSAQE",
        ),
        source="p.cfg",
    )
    payload = _nodedb_payload()
    payload["nodes"][0]["publicKey"] = base64.b64encode(pub).decode()
    nodedb = backup.parse_nodedb_json(json.dumps(payload).encode(), source="n.json")
    bundle = backup.merge_backups(profile=profile, nodedb=nodedb)
    node_id = NodeId.from_int(2697256389)

    live = backup.live_config_from_backup(bundle, node_id=node_id)

    assert live.hw_model == "TBEAM"
    assert live.firmware_version == "2.6.11"
    assert live.value("lora", "region") == "EU_868"
    assert bundle.channel is not None


# --- suggest_node_ids_by_name ---------------------------------------------------


def _observation(node_id: NodeId, *, long_name: str) -> NodeObservation:
    from datetime import UTC, datetime

    return NodeObservation(
        node_id=node_id,
        source=SOURCE_LORANET,
        observed_at=datetime.now(tz=UTC),
        long_name=long_name,
    )


def test_suggest_node_ids_by_name_matches_case_and_whitespace_insensitively() -> None:
    target = NodeId.from_hex("a0cb5cc4")
    other = NodeId.from_hex("deadbeef")
    observations = {
        target: _observation(target, long_name="  Meshtastic MT01  "),
        other: _observation(other, long_name="Something Else"),
    }
    result = backup.suggest_node_ids_by_name(observations, long_name="meshtastic mt01")
    assert result == (target,)


def test_suggest_node_ids_by_name_empty_query_matches_nothing() -> None:
    node_id = NodeId.from_hex("a0cb5cc4")
    observations = {node_id: _observation(node_id, long_name="")}
    assert backup.suggest_node_ids_by_name(observations, long_name="   ") == ()


def test_suggest_node_ids_by_name_returns_every_match_sorted() -> None:
    a = NodeId.from_hex("deadbeef")
    b = NodeId.from_hex("a0cb5cc4")
    observations = {
        a: _observation(a, long_name="Duplicate Name"),
        b: _observation(b, long_name="Duplicate Name"),
    }
    result = backup.suggest_node_ids_by_name(observations, long_name="Duplicate Name")
    assert result == (b, a)


# --- load_backup (filesystem) ---------------------------------------------------


def test_load_backup_reads_and_sniffs_a_real_file(tmp_path) -> None:
    path = tmp_path / "profile.cfg"
    path.write_bytes(_make_cfg_bytes())
    parsed = backup.load_backup(path)
    assert isinstance(parsed, backup.ProfileBackup)
    assert parsed.source == str(path)


def test_load_backup_raises_for_unreadable_format(tmp_path) -> None:
    path = tmp_path / "garbage.bin"
    path.write_bytes(b"\x00\x01\x02not any known format\xff\xfe")
    with pytest.raises(BackupParseError):
        backup.load_backup(path)


def test_load_backup_raises_for_missing_file(tmp_path) -> None:
    with pytest.raises(BackupParseError):
        backup.load_backup(tmp_path / "does-not-exist.cfg")
