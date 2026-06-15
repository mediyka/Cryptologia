import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from core.audit import AuditManager
from core.clipboard.clipboard_service import ClipboardService
from core.clipboard.platform_adapter import InMemoryClipboardAdapter
from core.events import EventBus, event_bus


class UnlockedState:
    is_locked = False


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


class FakeEntryManager:
    def __init__(self, entries):
        self.entries = entries
        self.requested_ids = []

    def get_entry(self, entry_id):
        self.requested_ids.append(entry_id)
        if entry_id not in self.entries:
            raise ValueError("entry not found")
        return self.entries[entry_id]


class RecordingDB:
    def __init__(self):
        self.executed = []

    def execute(self, query, params=()):
        self.executed.append((query, params))


def make_service():
    adapter = InMemoryClipboardAdapter()
    events = EventBus()
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=MemoryConfig({"clipboard_timeout": "never"}),
        state=UnlockedState(),
        register_exit_handler=False,
    )
    return service, adapter, events


def test_int_1_clipboard_fetches_decrypted_value_through_entry_manager():
    service, adapter, _ = make_service()
    entry_manager = FakeEntryManager(
        {
            "entry-1": {
                "id": "entry-1",
                "username": "fresh-user",
                "password": "fresh-password",
            }
        }
    )

    assert service.copy_entry_field(entry_manager, "entry-1", "password")

    assert entry_manager.requested_ids == ["entry-1"]
    assert adapter.get_clipboard_content() == "fresh-password"
    assert service.get_clipboard_status().source_entry_id == "entry-1"


def test_int_1_entry_policy_can_block_clipboard_copy():
    service, adapter, _ = make_service()
    entry_manager = FakeEntryManager(
        {
            "entry-locked": {
                "id": "entry-locked",
                "username": "user",
                "password": "must-not-copy",
                "never_copy_to_clipboard": True,
            }
        }
    )

    with pytest.raises(PermissionError):
        service.copy_entry_field(entry_manager, "entry-locked", "password")

    assert adapter.get_clipboard_content() == ""


def test_int_1_entry_policy_can_block_specific_fields():
    service, adapter, _ = make_service()
    entry_manager = FakeEntryManager(
        {
            "entry-field-policy": {
                "id": "entry-field-policy",
                "username": "allowed-user",
                "password": "blocked-password",
                "clipboard_policy": {"blocked_fields": ["password"]},
            }
        }
    )

    with pytest.raises(PermissionError):
        service.copy_entry_field(entry_manager, "entry-field-policy", "password")

    assert service.copy_entry_field(entry_manager, "entry-field-policy", "username")
    assert adapter.get_clipboard_content() == "allowed-user"


def test_int_2_audit_logs_clipboard_operations_without_plaintext():
    db = RecordingDB()
    AuditManager(db)

    event_bus.publish(
        "ClipboardCopied",
        {
            "data_type": "password",
            "source_entry_id": "entry-audit",
            "timeout": 30,
            "secret_value": "plain-password",
        },
    )

    query, params = db.executed[-1]
    details = json.loads(params[2])

    assert "audit_log" in query
    assert params[0] == "ClipboardCopied"
    assert params[1] == "entry-audit"
    assert details["entry_id"] == "entry-audit"
    assert details["data_type"] == "password"
    assert "plain-password" not in params[2]
    assert "secret_value" not in details


def test_int_2_audit_logs_security_triggers():
    db = RecordingDB()
    AuditManager(db)

    event_bus.publish(
        "ClipboardSuspiciousActivity",
        {
            "reason": "external_clipboard_access",
            "action": "accelerate_clear",
            "source_entry_id": "entry-security",
            "count": 1,
        },
    )

    _, params = db.executed[-1]
    details = json.loads(params[2])

    assert params[0] == "ClipboardSuspiciousActivity"
    assert params[1] == "entry-security"
    assert details["reason"] == "external_clipboard_access"
    assert details["action"] == "accelerate_clear"


def test_int_2_audit_redacts_entry_event_secrets():
    db = RecordingDB()
    AuditManager(db)

    event_bus.publish(
        "EntryCreated",
        {
            "entry_id": "entry-redacted",
            "data": {
                "title": "Private",
                "password": "plain-entry-password",
                "totp_secret": "plain-totp-secret",
            },
        },
    )

    _, params = db.executed[-1]
    details = json.loads(params[1])

    assert params[0] == "EntryCreated"
    assert details["data"]["password"] == "[redacted]"
    assert details["data"]["totp_secret"] == "[redacted]"
    assert "plain-entry-password" not in params[1]
    assert "plain-totp-secret" not in params[1]


def test_int_3_panic_mode_clears_clipboard_and_blocks_future_copies():
    service, adapter, events = make_service()

    assert service.copy_password("panic-secret", source_entry_id="entry-panic")
    events.publish("PanicModeActivated")

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False
    assert service.is_copy_blocked() is True
    with pytest.raises(PermissionError):
        service.copy_password("another-secret", source_entry_id="entry-panic")
