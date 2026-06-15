import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from core.audit import AuditManager
from core.clipboard.clipboard_service import ClipboardService, MAX_CLIPBOARD_CHARS
from core.clipboard.platform_adapter import InMemoryClipboardAdapter
from core.events import EventBus, event_bus


class UnlockedState:
    is_locked = False


class LockedState:
    is_locked = True


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


class RecordingDB:
    def __init__(self):
        self.executed = []

    def execute(self, query, params=()):
        self.executed.append((query, params))


def make_service(config=None, state=None):
    adapter = InMemoryClipboardAdapter()
    events = EventBus()
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=config if config is not None else MemoryConfig({"clipboard_timeout": "never"}),
        state=state or UnlockedState(),
        register_exit_handler=False,
    )
    return service, adapter, events


def test_sec_1_clipboard_secret_is_not_persisted_to_config_or_audit():
    secret = "no-persistence-secret"
    config = MemoryConfig({"clipboard_timeout": "never"})
    service, _, _ = make_service(config=config)
    db = RecordingDB()
    AuditManager(db)

    assert service.copy_password(secret, source_entry_id="entry-sec-1")
    event_bus.publish(
        "ClipboardCopied",
        {
            "data_type": "password",
            "source_entry_id": "entry-sec-1",
            "timeout": "never",
            "secret": secret,
            "clipboard_content": secret,
        },
    )

    assert secret not in json.dumps(config, ensure_ascii=False)
    for _, params in db.executed:
        assert secret not in json.dumps(params, ensure_ascii=False)


def test_sec_2_plaintext_is_not_kept_in_service_memory_buffers():
    secret = "process-isolation-secret"
    service, _, _ = make_service()

    assert service.copy_password(secret, source_entry_id="entry-sec-2")
    item = service.current_content

    assert item is not None
    assert secret.encode("utf-8") not in bytes(item._data)
    assert secret.encode("utf-8") not in bytes(item._mask)
    assert secret not in repr(item.__dict__)

    data_buffer = item._data
    mask_buffer = item._mask
    service.clear_clipboard("manual")

    assert all(byte == 0 for byte in data_buffer)
    assert all(byte == 0 for byte in mask_buffer)


@pytest.mark.parametrize("event_name", ["UserLoggedOut", "VaultLocked", "ApplicationLocked", "SessionLocked"])
def test_sec_3_clipboard_clears_on_lock_events(event_name):
    service, adapter, events = make_service()

    assert service.copy_password("clear-on-lock-secret", source_entry_id="entry-sec-3")
    events.publish(event_name)

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False


def test_sec_4_clipboard_input_validation_rejects_invalid_values():
    service, _, _ = make_service()

    with pytest.raises(TypeError):
        service.copy_to_clipboard(b"bytes-are-not-text", data_type="password")
    with pytest.raises(ValueError):
        service.copy_to_clipboard("", data_type="password")
    with pytest.raises(ValueError):
        service.copy_to_clipboard("bad\x00value", data_type="password")
    with pytest.raises(ValueError):
        service.copy_to_clipboard("secret", data_type="unsupported")
    with pytest.raises(ValueError):
        service.copy_to_clipboard("x" * (MAX_CLIPBOARD_CHARS + 1), data_type="password")


def test_sec_4_clipboard_operations_require_unlocked_vault():
    service, _, _ = make_service(state=LockedState())

    with pytest.raises(PermissionError):
        service.copy_password("locked-secret", source_entry_id="entry-sec-4")
