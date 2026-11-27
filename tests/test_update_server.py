import logging
import os
import threading
from collections import UserDict
from queue import Queue
from types import SimpleNamespace
from unittest import mock

import pytest

os.environ["SERVICE_MANIFEST_PATH"] = os.path.join(os.path.dirname(__file__), "..", "service_manifest.yml")

from assemblyline_v4_service.updater.updater import SOURCE_STATUS_KEY, SOURCE_UPDATE_TIME_KEY

from yara_.update_server import YaraUpdateServer


class FakeHash(UserDict):
    def set(self, key, value):
        self[key] = value


@pytest.fixture
def updater(tmp_path):
    os.makedirs(tmp_path / "yara" / "present")
    server = YaraUpdateServer.__new__(YaraUpdateServer)
    server.log = logging.getLogger("test")
    server.client = None
    server._update_dir = str(tmp_path)
    server.update_data_hash = FakeHash()
    server.update_queue = Queue()
    server.source_update_flag = threading.Event()

    def configure(*sources):
        server._service = SimpleNamespace(
            update_config=SimpleNamespace(
                sources=[SimpleNamespace(name=name, enabled=enabled) for name, enabled in sources]
            )
        )
        for name, _ in sources:
            server.update_data_hash.set(f"{name}.{SOURCE_UPDATE_TIME_KEY}", 100)
        return server

    with mock.patch("yara_.update_server.YaraValidator"):
        yield configure


def set_state(server, source, state):
    server.update_data_hash.set(f"{source}.{SOURCE_STATUS_KEY}", {"state": state, "message": ""})


def queued(server):
    return [server.update_queue.get() for _ in range(server.update_queue.qsize())]


def test_inventory_check_passes_with_present_source(updater):
    server = updater(("present", True))
    set_state(server, "present", "DONE")

    assert server._inventory_check()
    assert not queued(server) and not server.source_update_flag.is_set()


def test_inventory_check_retasks_missing_sources(updater):
    server = updater(("present", True), ("missing", True))
    set_state(server, "missing", "DONE")

    assert server._inventory_check()
    assert queued(server) == ["missing"]
    assert server.update_data_hash[f"missing.{SOURCE_UPDATE_TIME_KEY}"] == 0
    assert server.source_update_flag.is_set()


def test_inventory_check_ignores_disabled_sources(updater):
    server = updater(("present", True), ("disabled", False))
    set_state(server, "disabled", "DONE")

    server._inventory_check()

    assert not queued(server) and not server.source_update_flag.is_set()
    assert server.update_data_hash[f"disabled.{SOURCE_UPDATE_TIME_KEY}"] == 100


def test_inventory_check_ignores_errored_sources(updater):
    server = updater(("present", True), ("failing", True))
    set_state(server, "failing", "ERROR")

    server._inventory_check()

    assert not queued(server) and not server.source_update_flag.is_set()
    assert server.update_data_hash[f"failing.{SOURCE_UPDATE_TIME_KEY}"] == 100


def test_inventory_check_triggers_for_never_attempted_sources(updater):
    server = updater(("present", True), ("new", True))

    server._inventory_check()

    assert not queued(server) and server.source_update_flag.is_set()


def test_inventory_check_skips_when_update_already_pending(updater):
    server = updater(("present", True), ("missing", True))
    set_state(server, "missing", "DONE")
    server.source_update_flag.set()

    server._inventory_check()

    assert not queued(server)
    assert server.update_data_hash[f"missing.{SOURCE_UPDATE_TIME_KEY}"] == 100
