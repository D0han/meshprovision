"""Tests for admin-key resolution in meshprovision.cli.provision."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest

from meshprovision.cli.provision import resolve_admin_keys
from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.db.schema import KeyType

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.crypto.keys import KeyPair

pytestmark = pytest.mark.unit

_LOGGER_NAME = "meshprovision.cli.provision"

_LOW_ENTROPY_PUBLIC = bytes([0x0F, 0x33, 0x55, 0x66]) * 8
"""Four distinct byte values -- trips the low-entropy check at warning severity only."""


@pytest.fixture
def keys(empty_ods: Path) -> KeyRepository:
    db = OdsDatabase(empty_ods)
    db.load()
    return KeyRepository(db)


def _template_with_admin(*refs: str) -> TemplateConfig:
    return load_template_text("version: 1\n").model_copy(update={"admin_nodes": refs})


def _audit_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.getMessage().startswith("admin key ")]


def test_soft_audit_finding_logs_a_warning(
    keys: KeyRepository, caplog: pytest.LogCaptureFixture
) -> None:
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, _LOW_ENTROPY_PUBLIC))

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        resolved = resolve_admin_keys(keys, _template_with_admin("ADMIN1"), known_bad=frozenset())

    assert resolved[0].audit_ok is True
    records = _audit_records(caplog)
    assert [record.levelno for record in records] == [logging.WARNING]
    assert "ADMIN1_pub" in records[0].getMessage()


def test_compromised_admin_key_logs_an_error(
    keys: KeyRepository, keypair: KeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    keys.upsert(KeyRecord.from_material("ADMIN1", KeyType.ADMIN_PUBLIC, keypair.public))

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        resolved = resolve_admin_keys(
            keys, _template_with_admin("ADMIN1"), known_bad=frozenset({keypair.public})
        )

    assert resolved[0].audit_ok is False
    records = _audit_records(caplog)
    assert [record.levelno for record in records] == [logging.ERROR]
    assert "[critical]" in records[0].getMessage()
